"""
erdeniz_security/config.py — Merkezi güvenlik konfigürasyonu.
Tüm ErdenizTech projeleri bu ayarları kullanır. Hassas değerler env'den okunur.
"""
from __future__ import annotations

import os
from typing import Any

SECURITY_SETTINGS = {
    "KEY_ROTATION_DAYS": 90,
    "HASH_ALGORITHM": "argon2id",
    "MIN_PASSWORD_LENGTH": 12,
    "SESSION_TIMEOUT_MINUTES": 30,
    "MAX_LOGIN_ATTEMPTS": 5,
    "LOCKOUT_DURATION_MINUTES": 30,
    "AUDIT_LOG_ENABLED": True,
    "SECURE_HEADERS_ENABLED": True,
}


def _safe_config(key: str) -> Any:
    try:
        from decouple import config as decouple_config
        return decouple_config(key, default="")
    except Exception:
        return os.environ.get(key, "")


def get_security_settings(project_name: str | None = None) -> dict[str, Any]:
    """Proje adına göre güvenlik ayarları (varsayılan: MAX seviye)."""
    out = dict(SECURITY_SETTINGS)
    out["project_name"] = project_name or "default"
    return out


def validate_configuration() -> list[str]:
    """Eksik env ve güvensiz ayarları kontrol eder; AppConfig.ready'de çağrılabilir."""
    errors: list[str] = []
    for key in ("SECRET_KEY", "FIELD_ENCRYPTION_KEY", "ERDENIZ_ENCRYPTION_KEY"):
        if not (os.environ.get(key) or _safe_config(key)):
            errors.append(f"Ortam değişkeni eksik veya boş: {key}")
    try:
        from decouple import config as decouple_config
        if decouple_config("DEBUG", default=True, cast=bool):
            errors.append("DEBUG=True production ortamında kapatılmalı.")
    except Exception:
        pass
    return errors


def get_django_security_settings() -> dict[str, Any]:
    """Django settings için güvenlik bloğu. FIELD_ENCRYPTION_KEY env'den."""
    field_key = os.environ.get("FIELD_ENCRYPTION_KEY", "")
    return {
        "PASSWORD_HASHERS": [
            "django.contrib.auth.hashers.Argon2PasswordHasher",
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
        ],
        "AUTHENTICATION_BACKENDS": [
            "axes.backends.AxesStandaloneBackend",
            "django.contrib.auth.backends.ModelBackend",
        ],
        "AUTH_PASSWORD_VALIDATORS": [
            {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
            {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
            {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
            {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
        ],
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_AGE": 1800,
        "SESSION_EXPIRE_AT_BROWSER_CLOSE": True,
        "SESSION_ENGINE": "django.contrib.sessions.backends.db",
        "CSRF_COOKIE_SECURE": True,
        "CSRF_COOKIE_HTTPONLY": True,
        "CSRF_COOKIE_SAMESITE": "Lax",
        "SECURE_SSL_REDIRECT": True,
        "SECURE_PROXY_SSL_HEADER": ("HTTP_X_FORWARDED_PROTO", "https"),
        "SECURE_HSTS_SECONDS": 31536000,
        "SECURE_HSTS_INCLUDE_SUBDOMAINS": True,
        "SECURE_HSTS_PRELOAD": True,
        "SECURE_BROWSER_XSS_FILTER": True,
        "SECURE_CONTENT_TYPE_NOSNIFF": True,
        "X_FRAME_OPTIONS": "DENY",
        "AXES_FAILURE_LIMIT": 5,
        "AXES_COOLOFF_TIME": 0.5,
        "AXES_LOCKOUT_CALLABLE": None,
        "AXES_RESET_ON_SUCCESS": True,
        "FIELD_ENCRYPTION_KEY": field_key,
    }


# Projeler: from erdeniz_security.config import get_django_security_settings
#          locals().update(get_django_security_settings())
# .env yüklendikten sonra çağrılırsa FIELD_ENCRYPTION_KEY doğru okunur.
DJANGO_SECURITY_SETTINGS = get_django_security_settings()
