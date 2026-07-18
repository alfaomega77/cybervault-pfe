from django.db.models import TextChoices
from django.utils.translation import gettext_lazy as _


class EventType(TextChoices):
    COMMAND_INGESTED = 'command.ingested', _('Command ingested')
    COMMAND_ACL_VIOLATION = 'command.acl_violation', _('Command ACL violation')
    SESSION_START = 'session.start', _('Session start')
    SESSION_END = 'session.end', _('Session end')
    SESSION_LIFECYCLE = 'session.lifecycle', _('Session lifecycle')
    LOGIN_SUCCESS = 'login.success', _('Login success')
    LOGIN_FAILED = 'login.failed', _('Login failed')
    FTP_TRANSFER = 'ftp.transfer', _('FTP transfer')


class PublisherType(TextChoices):
    FILE = 'file', _('File (local dev)')
    REDIS = 'redis', _('Redis Pub/Sub')
    HTTP = 'http', _('HTTP webhook')
    KINESIS = 'kinesis', _('AWS Kinesis')


SECURITY_EVENTS_REDIS_CHANNEL = 'fm.security_events'
