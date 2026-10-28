"""Explicit online screening for password creation, never sign-in."""

import hashlib
import http.client
import re
import ssl

from app.auth.corpus import CorpusUnavailable


def require_hibp_acceptable(password: str) -> None:
    if not 12 <= len(password) <= 128:
        raise ValueError("Password must contain 12 to 128 characters")
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    connection = http.client.HTTPSConnection(
        "api.pwnedpasswords.com", timeout=15, context=ssl.create_default_context()
    )
    try:
        connection.request(
            "GET",
            "/range/" + digest[:5],
            headers={"Add-Padding": "true", "User-Agent": "EventCheckin-PasswordScreening"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise CorpusUnavailable(
                "Online password screening unavailable; credential change stopped"
            )
        content = response.read(2_000_001)
        if not content or len(content) > 2_000_000:
            raise CorpusUnavailable(
                "Invalid password screening response; credential change stopped"
            )
        lines = content.decode("ascii").splitlines()
        compromised = False
        for line in lines:
            match = re.fullmatch(r"([0-9A-F]{35}):([0-9]+)", line)
            if match is None:
                raise CorpusUnavailable(
                    "Invalid password screening response; credential change stopped"
                )
            if match[1] == digest[5:] and int(match[2]) > 0:
                compromised = True
    except (OSError, http.client.HTTPException, UnicodeError, ValueError):
        raise CorpusUnavailable(
            "Online password screening unavailable; credential change stopped"
        ) from None
    finally:
        connection.close()
    if compromised:
        raise ValueError("Choose a different password")
