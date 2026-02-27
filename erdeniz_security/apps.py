from django.apps import AppConfig


class ErdenizSecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "erdeniz_security"
    verbose_name = "ErdenizTech Güvenlik"

    def ready(self) -> None:
        from .config import validate_configuration
        for e in validate_configuration():
            import logging
            logging.getLogger(__name__).warning("ErdenizSecurity: %s", e)
