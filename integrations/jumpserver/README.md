# JumpServer integration plugin

Django application that publishes privileged-session events from JumpServer to CyberVault.

## Install (outline)

1. Copy this package into your JumpServer `apps/` tree as `ai_security`
2. Register the app in JumpServer settings (see `ai_security_settings.py`)
3. Set environment / `config.yml` keys from `deployment/jumpserver-ai-security.env.example`
4. Restart JumpServer Core and Celery workers
5. Confirm CyberVault receives events on `POST /events` with the shared bearer token

Keep CyberVault in **dry-run** until decisions look correct.
