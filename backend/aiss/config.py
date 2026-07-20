import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = BASE_DIR / 'config' / 'default_policy.yaml'


@dataclass
class Settings:
    consumer_mode: str = os.getenv('AISS_CONSUMER_MODE', 'file')
    redis_url: str = os.getenv('AISS_REDIS_URL', 'redis://127.0.0.1:6379/10')
    redis_channel: str = os.getenv('AISS_REDIS_CHANNEL', 'fm.security_events')
    events_file: str = os.getenv('AISS_EVENTS_FILE', '')
    policy_path: str = os.getenv('AISS_POLICY_PATH', str(DEFAULT_POLICY_PATH))
    jumpserver_url: str = os.getenv('AISS_JUMPSERVER_URL', '')
    jumpserver_token: str = os.getenv('AISS_JUMPSERVER_TOKEN', '')
    dry_run: bool = os.getenv('AISS_DRY_RUN', 'true').lower() in ('1', 'true', 'yes')
    decision_log_path: str = os.getenv(
        'AISS_DECISION_LOG_PATH',
        str(BASE_DIR / 'data' / 'decisions.jsonl'),
    )
    feature_store_path: str = os.getenv(
        'AISS_FEATURE_STORE_PATH',
        str(BASE_DIR / 'data' / 'feature_store.json'),
    )
    baselines_path: str = os.getenv(
        'AISS_BASELINES_PATH',
        str(BASE_DIR / 'data' / 'user_baselines.json'),
    )
    ml_model_dir: str = os.getenv(
        'AISS_ML_MODEL_DIR',
        str(BASE_DIR / 'data' / 'models'),
    )
    http_ingest_enabled: bool = os.getenv('AISS_HTTP_INGEST', 'true').lower() in ('1', 'true', 'yes')
    http_ingest_port: int = int(os.getenv('AISS_HTTP_INGEST_PORT', '8090'))
    webhook_token: str = os.getenv('AISS_WEBHOOK_TOKEN', '')
    user_config_path: str = os.getenv(
        'AISS_USER_CONFIG_PATH',
        str(BASE_DIR / 'data' / 'user_config.json'),
    )
    web_root: str = os.getenv('AISS_WEB_ROOT', str(BASE_DIR / 'web'))
    public_url: str = os.getenv('AISS_PUBLIC_URL', 'http://localhost:8090')
    users_path: str = os.getenv('AISS_USERS_PATH', str(BASE_DIR / 'data' / 'users.json'))
    sessions_path: str = os.getenv('AISS_SESSIONS_PATH', str(BASE_DIR / 'data' / 'sessions.json'))
    integration_state_path: str = os.getenv(
        'AISS_INTEGRATION_STATE_PATH',
        str(BASE_DIR / 'data' / 'integration_state.json'),
    )
    behavior_rules_path: str = os.getenv(
        'AISS_BEHAVIOR_RULES_PATH',
        str(BASE_DIR / 'data' / 'behavior_rules.json'),
    )


from typing import Optional


def load_policy(path: Optional[str] = None):
    policy_path = path or settings.policy_path
    with open(policy_path, encoding='utf-8') as fp:
        return yaml.safe_load(fp)


settings = Settings()
