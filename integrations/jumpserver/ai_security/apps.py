from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class AiSecurityConfig(AppConfig):
    name = 'ai_security'
    verbose_name = _('AI Security')

    def ready(self):
        from . import signal_handlers  # noqa
