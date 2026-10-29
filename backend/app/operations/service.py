"""Authorized bulk-registration, gate redemption, attendance and export services."""

import csv
import hashlib
import io
import logging
import os
import zipfile
from datetime import UTC, datetime
from uuid import UUID, uuid4, uuid5
from xml.etree import ElementTree

from sqlalchemy import and_, func, null, or_, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.service import AuthService
from app.db.models import (
    CheckinAttempt,
    Event,
    EventAssignment,
    EventConfigAudit,
    EventFormVersion,
    Gate,
    JobRecord,
    ParticipantImport,
    ParticipantImportRow,
    Registration,
    RegistrationConsent,
    RegistrationNoticeVersion,
    SecurityAuditEvent,
    Ticket,
    TicketDeliveryIntent,
)
from app.db.session import authorized_tenant_session
from app.registration.service import (
    RegistrationInvalid,
    normalize_email,
    normalize_name,
    normalize_phone,
    validate_answers,
)
from app.tickets.crypto import TicketKeyring
from app.worker.jobs import enqueue_job

MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_IMPORT_ROWS = 10_000
IMPORT_CHUNK_ROWS = 200
logger = logging.getLogger(__name__)


class OperationDenied(ValueError):
    pass


def _redemption_result(outcome: str, reason_code: str, confirmed_at: datetime) -> dict[str, object]:
    logger.info(
        "gate_redemption",
        extra={"outcome": outcome, "reason_code": reason_code},
    )
    return {
        "outcome": outcome,
        "reason_code": reason_code,
        "confirmed_at": confirmed_at.isoformat(),
    }


def _csv_rows(content: bytes) -> tuple[list[str], list[dict[str, str]]]:
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise OperationDenied("CSV must use UTF-8 encoding") from exc
    reader = csv.DictReader(io.StringIO(decoded))
    if not reader.fieldnames or any(not value.strip() for value in reader.fieldnames):
        raise OperationDenied("The file must have a non-empty header row")
    columns = [value.strip() for value in reader.fieldnames]
    if len(columns) != len(set(columns)) or len(columns) > 100:
        raise OperationDenied("Column names must be unique")
    reader.fieldnames = columns
    rows: list[dict[str, str]] = []
    for raw in reader:
        if raw.get(None):
            raise OperationDenied("A row contains more values than the header")
        normalized = {column: (raw.get(column) or "").strip() for column in columns}
        if any(normalized.values()):
            rows.append(normalized)
        if len(rows) > MAX_IMPORT_ROWS:
            raise OperationDenied("The file exceeds 10,000 participant rows")
    return columns, rows


def _xlsx_rows(content: bytes) -> tuple[list[str], list[dict[str, str]]]:
    """Read the first XLSX worksheet without macros, formulas or external links."""
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > 256 or sum(item.file_size for item in members) > 50 * 1024 * 1024:
                raise OperationDenied("The XLSX workbook is too complex")
            names = {item.filename for item in members}
            if any(
                name.startswith("xl/externalLinks/")
                or name.endswith("vbaProject.bin")
                or name.endswith("connections.xml")
                for name in names
            ):
                raise OperationDenied("Macros and external workbook links are not supported")
            if "xl/worksheets/sheet1.xml" not in names:
                raise OperationDenied("The workbook has no first worksheet")
            shared: list[str] = []
            if "xl/sharedStrings.xml" in names:
                root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
                shared = ["".join(node.itertext()) for node in root.findall(f"{ns}si")]
            root = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    except (zipfile.BadZipFile, ElementTree.ParseError, KeyError) as exc:
        raise OperationDenied("The XLSX workbook is invalid") from exc

    matrix: list[list[str]] = []
    for row in root.findall(f".//{ns}row"):
        cells: dict[int, str] = {}
        for cell in row.findall(f"{ns}c"):
            if cell.find(f"{ns}f") is not None:
                raise OperationDenied("Spreadsheet formulas are not supported")
            ref = cell.attrib.get("r", "A1")
            letters = "".join(char for char in ref if char.isalpha()).upper()
            index = 0
            for char in letters:
                index = index * 26 + ord(char) - 64
            index -= 1
            if not 0 <= index < 100:
                raise OperationDenied("The XLSX worksheet exceeds 100 columns")
            kind = cell.attrib.get("t")
            value = cell.find(f"{ns}v")
            if kind == "inlineStr":
                inline = cell.find(f"{ns}is")
                rendered = "" if inline is None else "".join(inline.itertext())
            elif value is None:
                rendered = ""
            elif kind == "s":
                try:
                    rendered = shared[int(value.text or "-1")]
                except (IndexError, ValueError):
                    rendered = ""
            elif kind == "b":
                rendered = "true" if value.text == "1" else "false"
            else:
                rendered = value.text or ""
            if len(rendered) > 5_000:
                raise OperationDenied("A spreadsheet cell exceeds 5,000 characters")
            cells[index] = rendered.strip()
        if cells:
            width = max(cells) + 1
            matrix.append([cells.get(index, "") for index in range(width)])
        if len(matrix) > MAX_IMPORT_ROWS + 1:
            raise OperationDenied("The workbook exceeds 10,000 participant rows")
    if not matrix:
        raise OperationDenied("The workbook is empty")
    columns = [value.strip() for value in matrix[0]]
    if (
        any(not value for value in columns)
        or len(columns) != len(set(columns))
        or len(columns) > 100
    ):
        raise OperationDenied("Column names must be non-empty and unique")
    rows = []
    for values in matrix[1:]:
        if any(values[len(columns) :]):
            raise OperationDenied("A row contains values beyond the header columns")
        values += [""] * (len(columns) - len(values))
        record = {column: values[index].strip() for index, column in enumerate(columns)}
        if any(record.values()):
            rows.append(record)
    return columns, rows


def parse_import(file_name: str, content: bytes) -> tuple[list[str], list[dict[str, str]]]:
    if not content or len(content) > MAX_IMPORT_BYTES:
        raise OperationDenied("Upload a file no larger than 10 MB")
    suffix = os.path.splitext(file_name.lower())[1]
    if suffix == ".csv":
        result = _csv_rows(content)
    elif suffix == ".xlsx":
        result = _xlsx_rows(content)
    else:
        raise OperationDenied("Upload a CSV or XLSX file")
    if not result[1]:
        raise OperationDenied("The file has no participant rows")
    return result


def csv_safe(value: object) -> str:
    """Prevent attacker-controlled cells from becoming spreadsheet formulas."""
    rendered = "" if value is None else str(value)
    if rendered.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + rendered
    return rendered


def _import_view(batch: ParticipantImport) -> dict[str, object]:
    return {
        "import_id": str(batch.id),
        "event_id": str(batch.event_id),
        "file_name": batch.file_name,
        "status": batch.status,
        "row_count": batch.row_count,
        "valid_count": batch.valid_count,
        "invalid_count": batch.invalid_count,
        "duplicate_count": batch.duplicate_count,
        "imported_count": batch.imported_count,
        "progress": round(
            100
            * (batch.imported_count + batch.invalid_count + batch.duplicate_count)
            / batch.row_count
        )
        if batch.row_count
        else 100,
        "created_at": batch.created_at.isoformat(),
        "validated_at": batch.validated_at.isoformat() if batch.validated_at else None,
        "committed_at": batch.committed_at.isoformat() if batch.committed_at else None,
    }


class EventOperationsService:
    def __init__(
        self,
        engine: Engine,
        auth: AuthService | None,
        keys: TicketKeyring | None = None,
        privacy_notices_enabled: bool = True,
    ) -> None:
        self.engine, self.auth, self.keys = engine, auth, keys
        self.privacy_notices_enabled = privacy_notices_enabled

    def _scope(
        self, host: str, token: str, permission: str, event_id: UUID, gate_id: UUID | None = None
    ) -> tuple[UUID, UUID]:
        if self.auth is None:
            raise OperationDenied("Event operations unavailable")
        tenant = self.auth.authorize(host, token, permission, event_id, gate_id)
        user, _, _ = self.auth.current(host, token)
        return tenant, user.id

    def preview_import(
        self, host: str, token: str, event_id: UUID, file_name: str, content: bytes
    ) -> dict[str, object]:
        tenant, actor = self._scope(host, token, "attendee.export", event_id)
        columns, rows = parse_import(file_name, content)
        digest = hashlib.sha256(content).digest()
        with authorized_tenant_session(self.engine, tenant) as db:
            if db.scalar(select(Event.id).where(Event.id == event_id)) is None:
                raise OperationDenied("Event unavailable")
            existing = db.scalar(
                select(ParticipantImport).where(
                    ParticipantImport.event_id == event_id,
                    ParticipantImport.file_sha256 == digest,
                )
            )
            if existing is not None:
                sample = list(
                    db.scalars(
                        select(ParticipantImportRow)
                        .where(ParticipantImportRow.import_id == existing.id)
                        .order_by(ParticipantImportRow.row_number)
                        .limit(8)
                    )
                )
                return {
                    **_import_view(existing),
                    "columns": list(sample[0].raw_data) if sample else columns,
                    "sample": [item.raw_data for item in sample],
                    "reused": True,
                }
            batch = ParticipantImport(
                tenant_id=tenant,
                event_id=event_id,
                created_by=actor,
                file_name=os.path.basename(file_name)[:240],
                file_sha256=digest,
                row_count=len(rows),
            )
            db.add(batch)
            db.flush()
            db.add_all(
                ParticipantImportRow(
                    tenant_id=tenant,
                    event_id=event_id,
                    import_id=batch.id,
                    row_number=index,
                    raw_data=row,
                )
                for index, row in enumerate(rows, start=2)
            )
            return {
                **_import_view(batch),
                "columns": columns,
                "sample": rows[:8],
                "reused": False,
            }

    @staticmethod
    def _mapping(
        mapping: dict[str, object],
    ) -> tuple[str, str, str | None, str | None, dict[str, str]]:
        name = mapping.get("full_name")
        email = mapping.get("email")
        if name is not None and not isinstance(name, str):
            raise OperationDenied("The name mapping is invalid")
        if not isinstance(email, str) or not email.strip():
            raise OperationDenied("Map the email field")
        phone = mapping.get("phone")
        if phone is not None and not isinstance(phone, str):
            raise OperationDenied("The phone mapping is invalid")
        external = mapping.get("external_ref")
        if external is not None and not isinstance(external, str):
            raise OperationDenied("The external reference mapping is invalid")
        raw_custom = mapping.get("custom", {})
        if not isinstance(raw_custom, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in raw_custom.items()
        ):
            raise OperationDenied("Custom-field mappings are invalid")
        custom = {str(key): str(value) for key, value in raw_custom.items()}
        return (
            name.strip() if name and name.strip() else "",
            email.strip(),
            phone.strip() if phone and phone.strip() else None,
            external,
            custom,
        )

    @staticmethod
    def _active_notice(db: Session, tenant: UUID) -> RegistrationNoticeVersion:
        notice = db.scalar(
            select(RegistrationNoticeVersion).where(
                RegistrationNoticeVersion.tenant_id == tenant,
                RegistrationNoticeVersion.active.is_(True),
                RegistrationNoticeVersion.approved_at.is_not(None),
            )
        )
        if notice is None:
            raise OperationDenied(
                "No active approved privacy notice is available. "
                "Ask a platform administrator to approve and activate one."
            )
        if hashlib.sha256(notice.body.encode("utf-8")).digest() != notice.sha256:
            raise OperationDenied(
                "Approved privacy notice integrity check failed. Contact a platform administrator."
            )
        return notice

    def import_policy_status(self, host: str, token: str, event_id: UUID) -> dict[str, object]:
        tenant, _ = self._scope(host, token, "attendee.export", event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            if db.get(Event, event_id) is None:
                raise OperationDenied("Event unavailable")
            if not self.privacy_notices_enabled:
                return {"available": True, "message": "Participant import available."}
            try:
                self._active_notice(db, tenant)
            except OperationDenied as exc:
                return {"available": False, "message": str(exc)}
            return {"available": True, "message": "Approved privacy notice available."}

    def validate_import(
        self,
        host: str,
        token: str,
        event_id: UUID,
        import_id: UUID,
        mapping: dict[str, object],
    ) -> dict[str, object]:
        tenant, _ = self._scope(host, token, "attendee.export", event_id)
        name_col, email_col, phone_col, external_col, custom_cols = self._mapping(mapping)
        with authorized_tenant_session(self.engine, tenant) as db:
            batch = db.scalar(
                select(ParticipantImport)
                .where(ParticipantImport.id == import_id, ParticipantImport.event_id == event_id)
                .with_for_update()
            )
            if batch is None or batch.status in {"queued", "processing", "completed"}:
                raise OperationDenied("Import is unavailable for validation")
            notice = self._active_notice(db, tenant) if self.privacy_notices_enabled else None
            event = db.scalar(select(Event).where(Event.id == event_id))
            if event is None:
                raise OperationDenied("Event registration form unavailable")
            form = db.scalar(
                select(EventFormVersion).where(
                    EventFormVersion.event_id == event_id,
                    EventFormVersion.version == event.form_schema_version,
                )
            )
            if form is None:
                raise OperationDenied("Event registration form unavailable")
            rows = list(
                db.scalars(
                    select(ParticipantImportRow)
                    .where(ParticipantImportRow.import_id == import_id)
                    .order_by(ParticipantImportRow.row_number)
                    .with_for_update()
                )
            )
            if rows:
                columns = set(rows[0].raw_data)
                mapped_columns = {email_col, *custom_cols.values()}
                if name_col:
                    mapped_columns.add(name_col)
                if phone_col:
                    mapped_columns.add(phone_col)
                if external_col:
                    mapped_columns.add(external_col)
                if not mapped_columns <= columns:
                    raise OperationDenied("A mapped source column is absent from the file")
            form_fields = form.schema.get("fields", [])
            if not isinstance(form_fields, list):
                raise OperationDenied("Event registration form unavailable")
            field_types = {
                str(field["key"]): field.get("type")
                for field in form_fields
                if isinstance(field, dict) and "key" in field
            }
            seen_email: set[str] = set()
            seen_phone: set[str] = set()
            valid = invalid = duplicate = 0
            for row in rows:
                errors: list[str] = []
                raw = row.raw_data
                try:
                    normalized: dict[str, object] = {
                        "full_name": normalize_name(str(raw.get(name_col, "")))
                        if name_col
                        else "Name not provided",
                        "email": normalize_email(str(raw.get(email_col, ""))),
                        "phone": normalize_phone(str(raw.get(phone_col, "")))
                        if phone_col and str(raw.get(phone_col, "")).strip()
                        else None,
                    }
                    external = str(raw.get(external_col, "")).strip() if external_col else ""
                    if external:
                        normalized["external_ref"] = external[:500]
                    answers = {
                        key: raw.get(column, "")
                        for key, column in custom_cols.items()
                        if raw.get(column, "") != ""
                    }
                    for key, value in list(answers.items()):
                        if field_types.get(key) == "checkbox":
                            lowered = str(value).strip().lower()
                            if lowered in {"yes", "true", "1"}:
                                answers[key] = True
                            elif lowered in {"no", "false", "0"}:
                                answers[key] = False
                    normalized["custom_answers"] = validate_answers(form.schema, answers)
                except RegistrationInvalid:
                    normalized = {}
                    errors.append("INVALID_FIELD")
                if normalized:
                    email = str(normalized["email"])
                    phone_value = normalized["phone"]
                    phone = str(phone_value) if phone_value is not None else None
                    if email in seen_email:
                        errors.append("DUPLICATE_EMAIL_IN_FILE")
                    if phone is not None and phone in seen_phone:
                        errors.append("DUPLICATE_PHONE_IN_FILE")
                    seen_email.add(email)
                    if phone is not None:
                        seen_phone.add(phone)
                    matches = [Registration.email == email]
                    if phone is not None:
                        matches.append(Registration.phone_e164 == phone)
                    exists = db.scalar(
                        select(Registration.id).where(
                            Registration.event_id == event_id,
                            Registration.deleted_at.is_(None),
                            or_(*matches),
                        )
                    )
                    if exists is not None:
                        errors.append("ALREADY_REGISTERED")
                row.normalized_data = normalized
                row.error_codes = errors
                if any(
                    code.startswith("DUPLICATE") or code == "ALREADY_REGISTERED" for code in errors
                ):
                    row.status = "duplicate"
                    duplicate += 1
                elif errors:
                    row.status = "invalid"
                    invalid += 1
                else:
                    row.status = "valid"
                    valid += 1
            batch.mapping = mapping
            batch.notice_version = notice.version if notice else None
            batch.lawful_basis = notice.lawful_basis if notice else None
            batch.valid_count, batch.invalid_count, batch.duplicate_count = (
                valid,
                invalid,
                duplicate,
            )
            batch.status = "validated"
            batch.validated_at = datetime.now(UTC)
            return {**_import_view(batch), "errors": self._row_errors(rows, 100)}

    @staticmethod
    def _row_errors(rows: list[ParticipantImportRow], limit: int) -> list[dict[str, object]]:
        return [
            {"row_number": row.row_number, "errors": row.error_codes}
            for row in rows
            if row.error_codes
        ][:limit]

    def commit_import(
        self,
        host: str,
        token: str,
        event_id: UUID,
        import_id: UUID,
        authorization_confirmed: bool,
    ) -> dict[str, object]:
        tenant, actor = self._scope(host, token, "attendee.export", event_id)
        if not authorization_confirmed:
            raise OperationDenied(
                "Confirm your authority and lawful basis before importing attendees"
            )
        with authorized_tenant_session(self.engine, tenant) as db:
            previous = db.scalar(
                select(ParticipantImport).where(
                    ParticipantImport.id == import_id,
                    ParticipantImport.event_id == event_id,
                )
            )
            if previous is None:
                raise OperationDenied("Import unavailable")
            if previous.status in {"queued", "processing", "completed"}:
                return _import_view(previous)
            if previous.status != "validated":
                raise OperationDenied("Validate rows before importing attendees")
            mapping = previous.mapping
        validated = self.validate_import(host, token, event_id, import_id, mapping)
        with authorized_tenant_session(self.engine, tenant) as db:
            batch = db.scalar(
                select(ParticipantImport).where(ParticipantImport.id == import_id).with_for_update()
            )
            if batch is None:
                raise OperationDenied("Import unavailable")
            event = db.scalar(select(Event).where(Event.id == event_id))
            if event is None or event.status != "published":
                raise OperationDenied("Publish the event before committing registrations")
            if batch.status in {"queued", "processing", "completed"}:
                return _import_view(batch)
            if batch.valid_count < 1:
                raise OperationDenied("No valid registrations are available to import")
            batch.authorization_confirmed_at = datetime.now(UTC)
            batch.authorization_confirmed_by = actor
            db.add(
                SecurityAuditEvent(
                    actor_user_id=actor,
                    tenant_id=tenant,
                    action="registration.import.authorized",
                    metadata_json={
                        "event_id": str(event_id),
                        "import_id": str(import_id),
                        "notice_version": batch.notice_version,
                    },
                )
            )
            batch.status = "queued"
            batch.current_job_id = enqueue_job(
                db,
                tenant_id=tenant,
                event_id=event_id,
                job_type="registration.import",
                idempotency_key=import_id,
                max_attempts=5,
            )
            validated.update(status="queued")
            return validated

    def process_import_job(self, db: Session, job: JobRecord) -> None:
        if job.event_id is None:
            raise OperationDenied("Import job lacks event scope")
        batch = db.scalar(
            select(ParticipantImport)
            .where(
                ParticipantImport.event_id == job.event_id,
                ParticipantImport.current_job_id == job.id,
            )
            .with_for_update()
        )
        if batch is None:
            raise OperationDenied("Import unavailable")
        if batch.status == "completed":
            return
        if batch.status not in {"queued", "processing"} or (
            self.privacy_notices_enabled and batch.notice_version is None
        ):
            raise OperationDenied("Import has not been validated")
        event = db.scalar(select(Event).where(Event.id == job.event_id))
        if event is None or event.status != "published":
            raise OperationDenied("Event unavailable")
        batch.status = "processing"
        notice = db.scalar(
            select(RegistrationNoticeVersion).where(
                RegistrationNoticeVersion.tenant_id == batch.tenant_id,
                RegistrationNoticeVersion.version == batch.notice_version,
                RegistrationNoticeVersion.active.is_(True),
                RegistrationNoticeVersion.approved_at.is_not(None),
            )
        )
        if self.privacy_notices_enabled and (
            notice is None
            or notice.lawful_basis != batch.lawful_basis
            or hashlib.sha256(notice.body.encode("utf-8")).digest() != notice.sha256
        ):
            raise OperationDenied("Approved import notice is no longer active")
        rows = list(
            db.scalars(
                select(ParticipantImportRow)
                .where(
                    ParticipantImportRow.import_id == batch.id,
                    ParticipantImportRow.status == "valid",
                )
                .order_by(ParticipantImportRow.row_number)
                .limit(IMPORT_CHUNK_ROWS)
                .with_for_update()
            )
        )
        imported = batch.imported_count
        duplicates = batch.duplicate_count
        for row in rows:
            registration_id = uuid4()
            data = row.normalized_data
            try:
                with db.begin_nested():
                    db.add(
                        Registration(
                            id=registration_id,
                            tenant_id=batch.tenant_id,
                            event_id=batch.event_id,
                            full_name=str(data["full_name"]),
                            email=str(data["email"]),
                            phone_e164=str(data["phone"]) if data.get("phone") else None,
                            custom_answers=data.get("custom_answers", {}),
                            form_schema_version=event.form_schema_version,
                            source="bulk",
                            external_ref=data.get("external_ref"),
                            status="registered",
                        )
                    )
                    db.flush()
                    if notice is not None:
                        db.add(
                            RegistrationConsent(
                                id=uuid4(),
                                tenant_id=batch.tenant_id,
                                event_id=batch.event_id,
                                registration_id=registration_id,
                                notice_version=notice.version,
                                notice_digest=notice.sha256,
                                lawful_basis=notice.lawful_basis,
                                acknowledged_at=null(),
                                marketing_opt_in=False,
                                source="bulk",
                            )
                        )
                    if event.registration_mode == "public":
                        enqueue_job(
                            db,
                            tenant_id=batch.tenant_id,
                            event_id=batch.event_id,
                            job_type="ticket.issue",
                            idempotency_key=registration_id,
                        )
            except IntegrityError as exc:
                if getattr(exc.orig, "sqlstate", None) != "23505":
                    raise
                row.status = "duplicate"
                row.error_codes = ["ALREADY_REGISTERED"]
                duplicates += 1
            else:
                row.status = "imported"
                row.registration_id = registration_id
                # The canonical registration now owns the participant PII. Keep
                # only row identity/status for idempotency and progress reporting.
                row.raw_data = {}
                row.normalized_data = {}
                imported += 1
        batch.imported_count = imported
        batch.duplicate_count = duplicates
        more = db.scalar(
            select(ParticipantImportRow.id)
            .where(
                ParticipantImportRow.import_id == batch.id,
                ParticipantImportRow.status == "valid",
            )
            .limit(1)
        )
        if more is None:
            batch.status = "completed"
            batch.committed_at = datetime.now(UTC)
            batch.current_job_id = None
        else:
            batch.current_job_id = enqueue_job(
                db,
                tenant_id=batch.tenant_id,
                event_id=batch.event_id,
                job_type="registration.import",
                idempotency_key=uuid5(batch.id, f"after-row-{rows[-1].row_number}"),
                max_attempts=5,
            )

    def import_status(
        self, host: str, token: str, event_id: UUID, import_id: UUID
    ) -> dict[str, object]:
        tenant, _ = self._scope(host, token, "attendee.export", event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            batch = db.scalar(
                select(ParticipantImport).where(
                    ParticipantImport.id == import_id, ParticipantImport.event_id == event_id
                )
            )
            if batch is None:
                raise OperationDenied("Import unavailable")
            view = _import_view(batch)
            if batch.current_job_id is not None:
                job = db.scalar(select(JobRecord).where(JobRecord.id == batch.current_job_id))
                if job is not None and job.status == "dead":
                    view["status"] = "failed"
            return view

    def import_errors_csv(self, host: str, token: str, event_id: UUID, import_id: UUID) -> str:
        tenant, _ = self._scope(host, token, "attendee.export", event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            if (
                db.scalar(
                    select(ParticipantImport.id).where(
                        ParticipantImport.id == import_id,
                        ParticipantImport.event_id == event_id,
                    )
                )
                is None
            ):
                raise OperationDenied("Import unavailable")
            rows = list(
                db.execute(
                    select(
                        ParticipantImportRow.row_number,
                        ParticipantImportRow.error_codes,
                    )
                    .where(ParticipantImportRow.import_id == import_id)
                    .order_by(ParticipantImportRow.row_number)
                ).all()
            )
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["row_number", "errors"])
        for row_number, error_codes in rows:
            if error_codes:
                writer.writerow([row_number, ";".join(error_codes)])
        return output.getvalue()

    def registrations(
        self,
        host: str,
        token: str,
        event_id: UUID,
        query: str = "",
        status: str = "",
        limit: int = 50,
        cursor: int = 0,
    ) -> dict[str, object]:
        tenant, _ = self._scope(host, token, "attendee.export", event_id)
        limit = max(1, min(limit, 200))
        cursor = max(cursor, 0)
        with authorized_tenant_session(self.engine, tenant) as db:
            statement = select(Registration).where(
                Registration.event_id == event_id, Registration.deleted_at.is_(None)
            )
            if status:
                statement = statement.where(Registration.status == status)
            if query.strip():
                pattern = f"%{query.strip()}%"
                statement = statement.where(
                    or_(Registration.full_name.ilike(pattern), Registration.email.ilike(pattern))
                )
            rows = list(
                db.scalars(
                    statement.order_by(Registration.registered_at.desc(), Registration.id)
                    .offset(cursor)
                    .limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            items = []
            for row in rows:
                ticket = db.scalar(
                    select(Ticket)
                    .where(Ticket.registration_id == row.id)
                    .order_by(Ticket.issued_at.desc())
                )
                delivery = (
                    db.scalar(
                        select(TicketDeliveryIntent)
                        .where(TicketDeliveryIntent.ticket_id == ticket.id)
                        .order_by(TicketDeliveryIntent.created_at.desc())
                    )
                    if ticket
                    else None
                )
                items.append(
                    {
                        "id": str(row.id),
                        "full_name": row.full_name,
                        "email": row.email,
                        "phone": row.phone_e164,
                        "source": row.source,
                        "status": row.status,
                        "registered_at": row.registered_at.isoformat(),
                        "ticket_status": ticket.status if ticket else "unavailable",
                        "delivery_status": delivery.status if delivery else "unavailable",
                    }
                )
            return {
                "registrations": items,
                "next_cursor": str(cursor + limit) if has_more else None,
            }

    def gate_session(self, host: str, token: str) -> dict[str, object]:
        if self.auth is None:
            raise OperationDenied("Gate access unavailable")
        user, member, _ = self.auth.current(host, token)
        tenant = member.tenant_id
        now = datetime.now(UTC)
        with Session(self.auth.engine) as identity, identity.begin():
            identity.execute(
                text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": str(tenant)}
            )
            assignments = list(
                identity.execute(
                    select(EventAssignment.event_id, EventAssignment.gate_id).where(
                        EventAssignment.tenant_id == tenant,
                        EventAssignment.user_id == user.id,
                        EventAssignment.gate_id.is_not(None),
                        EventAssignment.revoked_at.is_(None),
                        EventAssignment.valid_from <= now,
                        or_(
                            EventAssignment.valid_until.is_(None), EventAssignment.valid_until > now
                        ),
                    )
                ).all()
            )
        result = []
        with authorized_tenant_session(self.engine, tenant) as db:
            for event_id, gate_id in assignments:
                event = db.scalar(select(Event).where(Event.id == event_id))
                gate = db.scalar(select(Gate).where(Gate.id == gate_id))
                if event and gate and gate.status == "active":
                    result.append(
                        {
                            "event_id": str(event.id),
                            "event_name": event.name,
                            "gate_id": str(gate.id),
                            "gate_name": gate.name,
                            "event_status": event.status,
                        }
                    )
        return {"role": member.role, "assignments": result}

    def redeem(
        self, host: str, token: str, event_id: UUID, gate_id: UUID, credential: str
    ) -> dict[str, object]:
        if self.keys is None:
            raise OperationDenied("Ticket verification unavailable")
        tenant, scanner = self._scope(host, token, "checkin.perform", event_id, gate_id)
        digest = self.keys.digest(credential)
        version = self.keys.version_of(credential)
        now = datetime.now(UTC)
        with authorized_tenant_session(self.engine, tenant) as db:
            event = db.scalar(select(Event).where(Event.id == event_id))
            gate = db.scalar(select(Gate).where(Gate.id == gate_id, Gate.event_id == event_id))
            # Contextual rejection is a server-confirmed non-admission, not an
            # ambiguous transport error. Keep the legacy `invalid` outcome for
            # clients that do not yet understand reason_code.
            if event is None or event.status != "published":
                return _redemption_result("invalid", "EVENT_UNAVAILABLE", now)
            if gate is None or gate.status != "active":
                return _redemption_result("invalid", "GATE_UNAVAILABLE", now)
            if event.checkin_opens_at is None or event.checkin_closes_at is None:
                return _redemption_result("invalid", "CHECKIN_WINDOW_UNAVAILABLE", now)
            if now < event.checkin_opens_at:
                return _redemption_result("invalid", "CHECKIN_NOT_OPEN", now)
            if now >= event.checkin_closes_at:
                return _redemption_result("invalid", "CHECKIN_CLOSED", now)
            ticket = None
            if digest is not None and version is not None:
                ticket = db.scalar(
                    select(Ticket)
                    .where(
                        Ticket.event_id == event_id,
                        Ticket.key_version == version,
                        Ticket.token_digest == digest,
                    )
                    .with_for_update()
                )
            outcome = "invalid"
            reason_code = "INVALID_TICKET"
            if ticket is not None:
                outcome = {"active": "accepted", "used": "duplicate", "revoked": "revoked"}[
                    ticket.status
                ]
                reason_code = {
                    "accepted": "ACCEPTED",
                    "duplicate": "DUPLICATE_ADMISSION",
                    "revoked": "REVOKED_TICKET",
                }[outcome]
                if outcome == "accepted":
                    registration = db.scalar(
                        select(Registration).where(
                            Registration.id == ticket.registration_id,
                            Registration.event_id == event_id,
                        )
                    )
                    if (
                        registration is None
                        or registration.deleted_at is not None
                        or registration.status != "registered"
                    ):
                        outcome = "invalid"
                        reason_code = "INVALID_TICKET"
                    else:
                        ticket.status = "used"
                        ticket.redeemed_at = now
            db.add(
                CheckinAttempt(
                    tenant_id=tenant,
                    event_id=event_id,
                    gate_id=gate_id,
                    ticket_id=ticket.id if ticket and outcome != "invalid" else None,
                    registration_id=(
                        ticket.registration_id if ticket and outcome != "invalid" else None
                    ),
                    scanner_user_id=scanner,
                    outcome=outcome,
                    occurred_at=now,
                )
            )
            return _redemption_result(outcome, reason_code, now)

    def attendance(self, host: str, token: str, event_id: UUID) -> dict[str, object]:
        tenant, _ = self._scope(host, token, "report.view", event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            registered = (
                db.scalar(
                    select(func.count())
                    .select_from(Registration)
                    .where(
                        Registration.event_id == event_id,
                        Registration.deleted_at.is_(None),
                        Registration.status == "registered",
                    )
                )
                or 0
            )
            counts = dict(
                db.execute(
                    select(CheckinAttempt.outcome, func.count())
                    .where(CheckinAttempt.event_id == event_id)
                    .group_by(CheckinAttempt.outcome)
                ).all()
            )
            gate_rows = db.execute(
                select(Gate.id, Gate.name, func.count(CheckinAttempt.id))
                .outerjoin(
                    CheckinAttempt,
                    and_(CheckinAttempt.gate_id == Gate.id, CheckinAttempt.outcome == "accepted"),
                )
                .where(Gate.event_id == event_id)
                .group_by(Gate.id, Gate.name)
                .order_by(Gate.name)
            ).all()
            recent = db.execute(
                select(CheckinAttempt, Gate.name)
                .join(Gate, Gate.id == CheckinAttempt.gate_id)
                .where(CheckinAttempt.event_id == event_id)
                .order_by(CheckinAttempt.occurred_at.desc())
                .limit(30)
            ).all()
            checked_in = int(counts.get("accepted", 0))
            return {
                "event_id": str(event_id),
                "registered": int(registered),
                "checked_in": checked_in,
                "remaining": max(0, int(registered) - checked_in),
                "attendance_percent": round(checked_in * 100 / registered, 1)
                if registered
                else 0.0,
                "duplicate_scans": int(counts.get("duplicate", 0)),
                "invalid_scans": int(counts.get("invalid", 0)) + int(counts.get("revoked", 0)),
                "gates": [
                    {"gate_id": str(gate_id), "gate_name": name, "checked_in": int(count)}
                    for gate_id, name, count in gate_rows
                ],
                "recent": [
                    {
                        "outcome": attempt.outcome,
                        "gate_name": gate_name,
                        "occurred_at": attempt.occurred_at.isoformat(),
                    }
                    for attempt, gate_name in recent
                ],
                "refreshed_at": datetime.now(UTC).isoformat(),
            }

    def attendance_csv(self, host: str, token: str, event_id: UUID) -> str:
        tenant, actor = self._scope(host, token, "attendee.export", event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            accepted = (
                select(CheckinAttempt.registration_id, CheckinAttempt.occurred_at, Gate.name)
                .join(Gate, Gate.id == CheckinAttempt.gate_id)
                .where(CheckinAttempt.event_id == event_id, CheckinAttempt.outcome == "accepted")
                .subquery()
            )
            rows = db.execute(
                select(
                    Registration.id,
                    Registration.full_name,
                    Registration.email,
                    Registration.phone_e164,
                    Registration.status,
                    Registration.source,
                    accepted.c.occurred_at,
                    accepted.c.name,
                )
                .outerjoin(accepted, accepted.c.registration_id == Registration.id)
                .where(Registration.event_id == event_id, Registration.deleted_at.is_(None))
                .order_by(Registration.registered_at, Registration.id)
            ).all()
            db.add(
                EventConfigAudit(
                    tenant_id=tenant,
                    event_id=event_id,
                    actor_user_id=actor,
                    action="attendance.export",
                    metadata_json={"row_count": len(rows)},
                )
            )
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(
            [
                "registration_id",
                "full_name",
                "email",
                "phone_e164",
                "registration_status",
                "registration_source",
                "checked_in",
                "checked_in_at",
                "entry_gate",
            ]
        )
        for (
            registration_id,
            full_name,
            email,
            phone,
            registration_status,
            source,
            checked_at,
            gate_name,
        ) in rows:
            confirmed_at = checked_at if isinstance(checked_at, datetime) else None
            writer.writerow(
                [
                    registration_id,
                    csv_safe(full_name),
                    csv_safe(email),
                    csv_safe(phone),
                    csv_safe(registration_status),
                    csv_safe(source),
                    "yes" if confirmed_at else "no",
                    confirmed_at.isoformat() if confirmed_at else "",
                    csv_safe(gate_name),
                ]
            )
        return output.getvalue()
