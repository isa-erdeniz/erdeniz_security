# Minimal Django settings for erdeniz_security tests
import os

SECRET_KEY = "test-secret-key-for-erdeniz-security-tests"
DEBUG = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "erdeniz_security",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
USE_TZ = True
AUTH_USER_MODEL = "auth.User"
