"""ErdenizTech Security — Tek katman, tek paket."""

__version__ = "1.0.0"

# Encryption
from .encryption import (
    ErdenizEncryptor,
    FileEncryptor,
    DecryptionError,
    generate_key,
    generate_field_encryption_key,
    generate_password,
    hash_data,
    secure_compare,
)

# Config
from .config import (
    get_security_settings,
    get_django_security_settings,
    validate_configuration,
)

# Audit
from .audit import log_event, get_alerts, get_stats

# API Security (optional imports)
try:
    from .api_security import (
        ERDENIZ_JWT_SETTINGS,
        ERDENIZ_RATE_LIMITS,
        ErdenizAPIKeyManager,
        RequestSigner,
        secure_exception_handler,
    )
except ImportError:
    ERDENIZ_JWT_SETTINGS = None
    ERDENIZ_RATE_LIMITS = None
    ErdenizAPIKeyManager = None
    RequestSigner = None
    secure_exception_handler = None

# Network
try:
    from .network_guard import get_cors_settings, WebhookVerifier, SSLHelper, IPGuard
except ImportError:
    get_cors_settings = None
    WebhookVerifier = None
    SSLHelper = None
    IPGuard = None

# Fields (Django)
try:
    from .fields import (
        SecureCharField,
        SecureTextField,
        SecureEmailField,
        SecurePhoneField,
        SecureTCKimlikField,
        SecureFilePathField,
    )
except ImportError:
    SecureCharField = SecureTextField = SecureEmailField = None
    SecurePhoneField = SecureTCKimlikField = SecureFilePathField = None

# Decorators
from .decorators import (
    audit_log,
    require_api_key,
    require_jwt,
    require_signed_request,
    rate_limit,
    verify_webhook,
)

__all__ = [
    "__version__",
    "ErdenizEncryptor",
    "FileEncryptor",
    "DecryptionError",
    "generate_key",
    "generate_field_encryption_key",
    "generate_password",
    "hash_data",
    "secure_compare",
    "get_security_settings",
    "get_django_security_settings",
    "validate_configuration",
    "log_event",
    "get_alerts",
    "get_stats",
    "ERDENIZ_JWT_SETTINGS",
    "ERDENIZ_RATE_LIMITS",
    "ErdenizAPIKeyManager",
    "RequestSigner",
    "secure_exception_handler",
    "get_cors_settings",
    "WebhookVerifier",
    "SSLHelper",
    "IPGuard",
    "SecureCharField",
    "SecureTextField",
    "SecureEmailField",
    "SecurePhoneField",
    "SecureTCKimlikField",
    "SecureFilePathField",
    "audit_log",
    "require_api_key",
    "require_jwt",
    "require_signed_request",
    "rate_limit",
    "verify_webhook",
]
