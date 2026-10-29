"""Celery carries only opaque PostgreSQL job IDs."""

from importlib import import_module

from app.core.config import get_settings

settings = get_settings()
Celery = import_module("celery").Celery
celery_app = Celery(
    "eventcheckin", broker=settings.redis_url.get_secret_value() if settings.redis_url else None
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_backend=None,
    task_ignore_result=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    task_default_queue="eventcheckin-jobs",
)


def process_job(job_id: str) -> None:
    """Handlers register in their owning milestones; M1-04 has a test-only no-op."""
    from uuid import UUID

    from sqlalchemy import create_engine

    from app.core.config import Environment
    from app.worker.jobs import execute_job

    try:
        verified_job_id = UUID(job_id)
    except (TypeError, ValueError):
        # A malformed broker message must not be echoed into Celery error logs.
        return
    current = get_settings()
    if current.jobs_database_url is None:
        raise RuntimeError("Worker database role is not configured")
    operator = create_engine(current.jobs_database_url.get_secret_value(), pool_pre_ping=True)
    runtime = create_engine(current.database_url.get_secret_value(), pool_pre_ping=True)
    domain_worker = (
        create_engine(current.domain_worker_database_url.get_secret_value(), pool_pre_ping=True)
        if current.domain_worker_database_url
        else None
    )
    try:
        handlers = {}
        if current.app_env in {Environment.LOCAL, Environment.TEST}:
            handlers["internal_test_noop"] = lambda session, job: None
        if domain_worker is not None and current.fallback_domain_suffix:
            from app.tenancy.domains import (
                DisabledDomainProvider,
                DomainService,
                FixtureDomainProvider,
            )

            provider = (
                FixtureDomainProvider(current.local_domain_fixture)
                if current.local_domain_fixture
                and current.app_env in {Environment.LOCAL, Environment.TEST}
                else DisabledDomainProvider()
            )
            domains = DomainService(
                domain_worker, runtime, None, provider, current.fallback_domain_suffix
            )
            handlers["domain.reconcile"] = lambda session, job: domains.reconcile(
                job.id, job.tenant_id
            )
        if current.ticket_keyring_json is not None:
            from app.branding.assets import S3BrandingStorage
            from app.delivery.brevo import BrevoTransactionalClient
            from app.tickets.crypto import TicketKeyring
            from app.tickets.email import (
                BrevoTicketTransport,
                DisabledTicketTransport,
                LocalSmtpTicketTransport,
            )
            from app.tickets.service import TicketService
            from app.worker.storage import s3_storage

            ticket_transport = (
                BrevoTicketTransport(
                    BrevoTransactionalClient(current.brevo_api_key.get_secret_value()),
                    current.email_from,
                )
                if current.brevo_api_key and current.email_from
                else LocalSmtpTicketTransport(
                    current.email_smtp_host, current.email_smtp_port, current.email_from
                )
                if current.app_env in {Environment.LOCAL, Environment.TEST}
                and current.email_smtp_host
                and current.email_from
                else DisabledTicketTransport()
            )
            tickets = TicketService(
                runtime,
                None,
                TicketKeyring.from_settings(current),
                ticket_transport,
                S3BrandingStorage(s3_storage(current))
                if current.storage_bucket
                and current.storage_access_key
                and current.storage_secret_key
                else None,
            )
            handlers["ticket.issue"] = tickets.issue_job
            handlers["ticket.deliver"] = tickets.deliver_job
        from app.operations.service import EventOperationsService

        imports = EventOperationsService(
            runtime, None, None, privacy_notices_enabled=current.privacy_notices_enabled
        )
        handlers["registration.import"] = imports.process_import_job
        execute_job(operator, runtime, verified_job_id, handlers)
    finally:
        operator.dispose()
        runtime.dispose()
        if domain_worker is not None:
            domain_worker.dispose()


celery_app.task(name="eventcheckin.process_job", acks_late=True)(process_job)
