import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiss.notifications import alerter
from aiss.ingest.http_server import RequestTooLarge, _read_json_body
from aiss.web import auth_store, config_store
from aiss.web.integration_check import validate_jumpserver_url


class ConfigSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.tempdir.name) / 'config.json'
        self.path_patch = patch.object(config_store, 'config_path', return_value=self.config_path)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.tempdir.cleanup()

    def test_public_config_never_exposes_jumpserver_token(self):
        saved = config_store.save_user_config({
            'jumpserver_token': 'secret-token',
        })
        public = config_store.public_user_config(saved)

        self.assertNotIn('jumpserver_token', public)
        self.assertTrue(public['jumpserver_token_configured'])

    def test_user_preferences_cannot_disable_dry_run_when_env_locked(self):
        with patch.object(config_store.settings, 'dry_run', True):
            saved = config_store.save_user_preferences({
                'dry_run': False,
                'alert_email': 'soc@example.com',
            })
            self.assertTrue(saved['dry_run'])
            self.assertEqual(saved['alert_email'], 'soc@example.com')

    def test_user_can_toggle_dry_run_when_env_allows_live(self):
        with patch.object(config_store.settings, 'dry_run', False):
            live = config_store.save_user_preferences({'dry_run': False})
            self.assertFalse(live['dry_run'])
            self.assertFalse(config_store.effective_dry_run(live))
            safe = config_store.save_user_preferences({'dry_run': True})
            self.assertTrue(safe['dry_run'])
            self.assertTrue(config_store.effective_dry_run(safe))


class AuthSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        auth_store.USERS_FILE = Path(self.tempdir.name) / 'users.json'
        auth_store.SESSIONS_FILE = Path(self.tempdir.name) / 'sessions.json'
        auth_store.RESETS_FILE = Path(self.tempdir.name) / 'password_resets.json'

    def tearDown(self):
        self.tempdir.cleanup()

    def test_signup_requires_strong_password(self):
        with self.assertRaises(ValueError):
            auth_store.signup_user({'email': 'soc@example.com', 'password': 'too-short'})

        result = auth_store.signup_user({
            'email': 'soc@example.com',
            'password': 'correct-horse-battery',
        })
        self.assertTrue(result['token'])
        stored = json.loads(auth_store.USERS_FILE.read_text(encoding='utf-8'))['users'][0]
        self.assertNotIn('password', stored)

    @patch.dict('os.environ', {'AISS_SMTP_HOST': '', 'AISS_PUBLIC_URL': 'http://localhost:8090'}, clear=False)
    def test_password_reset_flow(self):
        auth_store.signup_user({
            'email': 'soc@example.com',
            'password': 'correct-horse-battery',
        })
        unknown = auth_store.request_password_reset('nobody@example.com')
        self.assertTrue(unknown['ok'])
        self.assertNotIn('reset_url', unknown)

        asked = auth_store.request_password_reset('soc@example.com')
        self.assertTrue(asked['ok'])
        self.assertIn('reset_url', asked)
        token = asked['reset_url'].split('token=')[1]

        auth_store.reset_password(token, 'new-secure-password')
        with self.assertRaises(ValueError):
            auth_store.login_user('soc@example.com', 'correct-horse-battery')
        logged = auth_store.login_user('soc@example.com', 'new-secure-password')
        self.assertTrue(logged['token'])
        with self.assertRaises(ValueError):
            auth_store.reset_password(token, 'another-password-xx')

    def test_update_profile_and_delete_account(self):
        created = auth_store.signup_user({
            'email': 'soc@example.com',
            'password': 'correct-horse-battery',
            'first_name': 'Ada',
            'last_name': 'Lovelace',
        })
        user_id = created['user']['id']
        tiny = (
            'data:image/png;base64,'
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='
        )
        updated = auth_store.update_profile(user_id, {
            'first_name': 'Grace',
            'last_name': 'Hopper',
            'company': 'Navy',
            'avatar': tiny,
        })
        self.assertEqual(updated['first_name'], 'Grace')
        self.assertEqual(updated['company'], 'Navy')
        self.assertTrue(updated['avatar'].startswith('data:image/png;base64,'))

        me = auth_store.get_user_by_token(created['token'])
        self.assertEqual(me['first_name'], 'Grace')

        with self.assertRaises(ValueError):
            auth_store.delete_account(user_id, 'wrong-password-xx')
        auth_store.delete_account(user_id, 'correct-horse-battery')
        self.assertIsNone(auth_store.get_user_by_token(created['token']))
        with self.assertRaises(ValueError):
            auth_store.login_user('soc@example.com', 'correct-horse-battery')

    def test_change_password_invalidates_sessions(self):
        created = auth_store.signup_user({
            'email': 'soc@example.com',
            'password': 'correct-horse-battery',
        })
        token = created['token']
        auth_store.change_password(
            created['user']['id'],
            'correct-horse-battery',
            'brand-new-password',
        )
        self.assertIsNone(auth_store.get_user_by_token(token))
        logged = auth_store.login_user('soc@example.com', 'brand-new-password')
        self.assertTrue(logged['token'])


    def test_signup_is_always_full_admin(self):
        result = auth_store.signup_user({
            'email': 'boss@example.com',
            'password': 'correct-horse-battery',
            'role': 'viewer',  # client must not be able to pick a weaker role
        })
        self.assertEqual(result['user']['role'], 'admin')
        stored = json.loads(auth_store.USERS_FILE.read_text(encoding='utf-8'))['users'][0]
        self.assertEqual(stored['role'], 'admin')
        # Simulate a legacy non-admin row — login upgrades it.
        stored['role'] = 'user'
        auth_store._save_json(auth_store.USERS_FILE, {'users': [stored]})
        logged = auth_store.login_user('boss@example.com', 'correct-horse-battery')
        self.assertEqual(logged['user']['role'], 'admin')
        again = json.loads(auth_store.USERS_FILE.read_text(encoding='utf-8'))['users'][0]
        self.assertEqual(again['role'], 'admin')


class EmailOnlyNotificationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        alerter.DEDUP_PATH = Path(self.tempdir.name) / 'dedup.json'
        alerter.OUTBOX_PATH = Path(self.tempdir.name) / 'outbox.jsonl'

    def tearDown(self):
        self.tempdir.cleanup()

    @patch.object(alerter, 'load_user_config', return_value={
        'notify_email': True,
        'alert_email': 'soc@example.com',
    })
    @patch.object(alerter.AlertNotifier, '_send_email', return_value={'ok': True, 'to': 'soc@example.com'})
    def test_alert_uses_email_only_and_escapes_html(self, _send, _config):
        notifier = alerter.AlertNotifier()
        event = {
            'event_id': 'event-1',
            'event_type': 'command.ingested',
            'user_id': '<admin>',
            'payload': {'input': '<script>alert(1)</script>'},
            'metadata': {'source': 'jumpserver'},
        }
        decision = {'risk_score': 0.9, 'action': 'ALERT_ANALYST', 'reasons': ['test']}
        result = notifier.notify_if_needed(event, decision, {'status': 'ok'})

        self.assertTrue(result['sent'])
        html = _send.call_args.args[3]
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)


class IntegrationSecurityTests(unittest.TestCase):
    def test_jumpserver_url_rejects_cloud_metadata(self):
        with self.assertRaises(ValueError):
            validate_jumpserver_url('http://169.254.169.254/latest/meta-data')

    def test_jumpserver_url_accepts_private_pam_endpoint(self):
        self.assertEqual(
            validate_jumpserver_url('https://jumpserver.internal/'),
            'https://jumpserver.internal',
        )


class RequestValidationTests(unittest.TestCase):
    @staticmethod
    def _handler(payload: bytes, declared_length=None):
        return type('Handler', (), {
            'headers': {'Content-Length': str(declared_length if declared_length is not None else len(payload))},
            'rfile': io.BytesIO(payload),
        })()

    def test_json_body_must_be_an_object(self):
        with self.assertRaisesRegex(ValueError, 'objet'):
            _read_json_body(self._handler(b'[]'))

    def test_json_body_size_is_limited_before_reading(self):
        with self.assertRaises(RequestTooLarge):
            _read_json_body(self._handler(b'', declared_length=3 * 1024 * 1024))


if __name__ == '__main__':
    unittest.main()
