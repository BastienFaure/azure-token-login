"""Disposable Azure CLI integration test with fabricated credentials only."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Lock
from types import SimpleNamespace

from azure.cli.core.auth.binary_cache import BinaryCache
from msal.individual_cache import _ExpiringMapping
from msal.throttled_http_client import NormalizedResponse

from test_importer import SUB, TENANT, jwt


class AzureCliIntegrationTests(unittest.TestCase):
    def test_extension_and_builtin_account_commands(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            config = base / 'config'
            config.mkdir(mode=0o700)
            wheel_dir = base / 'wheel'
            wheel_dir.mkdir()
            fabricated_token = jwt()
            replacement_token = jwt(oid=SUB)
            env = dict(os.environ, AZURE_CONFIG_DIR=str(config),
                       HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9',
                       ALL_PROXY='http://127.0.0.1:9', NO_PROXY='',
                       AZURE_CORE_ONLY_SHOW_ERRORS='true')
            subprocess.run([sys.executable, '-I', '-m', 'pip', 'wheel', '--no-deps',
                            '--no-build-isolation', str(source), '--wheel-dir', str(wheel_dir)],
                           env=env, check=True, capture_output=True, text=True)
            wheel, = wheel_dir.glob('*.whl')

            def az(*args):
                return subprocess.run(['az', *args, '--output', 'json'], env=env,
                                      capture_output=True, text=True, timeout=45)

            installed = az('extension', 'add', '--source', str(wheel), '--yes')
            self.assertEqual(installed.returncode, 0, installed.stderr)
            missing = az('token-login', 'import', '--subscription-id', SUB)
            self.assertNotEqual(missing.returncode, 0)
            imported = az('token-login', 'import', '--access-token', fabricated_token,
                          '--subscription-id', SUB)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(json.loads(imported.stdout)['importedSubscriptions'], 1)
            duplicate = az('token-login', 'import', '--access-token', replacement_token,
                           '--subscription-id', SUB)
            self.assertNotEqual(duplicate.returncode, 0)
            forced = az('token-login', 'import', '--access-token', replacement_token,
                        '--subscription-id', SUB, '-f')
            self.assertEqual(forced.returncode, 0, forced.stderr)
            account = az('account', 'show')
            self.assertEqual(account.returncode, 0, account.stderr)
            self.assertEqual(json.loads(account.stdout)['id'], SUB)
            self.assertEqual(json.loads(account.stdout)['tenantId'], TENANT)
            listed = az('account', 'list')
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertEqual(len(json.loads(listed.stdout)), 1)
            selected = az('account', 'set', '--subscription', SUB)
            self.assertEqual(selected.returncode, 0, selected.stderr)
            discovery_url = (f'https://login.microsoftonline.com/{TENANT}'
                             '/v2.0/.well-known/openid-configuration')
            discovery_response = SimpleNamespace(status_code=200, headers={}, text=json.dumps({
                'authorization_endpoint': f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize',
                'token_endpoint': f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token',
                'issuer': f'https://login.microsoftonline.com/{TENANT}/v2.0'}))
            cache_key = ('GET ' + discovery_url + ' hash=' +
                         hashlib.sha256(repr('').encode()).hexdigest() + ' 2xx')
            http_cache = BinaryCache(str(config / 'msal_http_cache.bin'))
            _ExpiringMapping(mapping=http_cache, capacity=1024, lock=Lock()).set(
                cache_key, NormalizedResponse(discovery_response), expires_in=3600)
            token_result = az('account', 'get-access-token', '--subscription', SUB)
            if token_result.returncode == 0:
                self.assertEqual(json.loads(token_result.stdout)['accessToken'], replacement_token)
                # A synthetic token cannot authorize an actual ARM request. Confirm
                # a built-in SDK command reaches transport instead of asking to log in.
                group_list = az('group', 'list', '--subscription', SUB)
                self.assertNotEqual(group_list.returncode, 0)
                self.assertIn('127.0.0.1', group_list.stderr)
                self.assertNotIn(fabricated_token, group_list.stderr)
            profile_path = config / 'azureProfile.json'
            profile = json.loads(profile_path.read_text(encoding='utf-8-sig'))
            profile['subscriptions'][0]['name'] = 'Updated subscription name'
            profile_path.write_text(json.dumps(profile))
            removed = az('token-login', 'remove', '--subscription-id', SUB)
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertEqual(json.loads(removed.stdout)['removedSubscriptions'], 1)
            old_spelling = az('token-login', 'import', '--access--token', fabricated_token,
                              '--subscription-id', SUB)
            self.assertNotEqual(old_spelling.returncode, 0)
            if token_result.returncode != 0 and ('127.0.0.1' in token_result.stderr or
                                                 'proxy' in token_result.stderr.lower()):
                self.skipTest('MSAL authority discovery needs network; synthetic offline cache hit '
                              'cannot exercise az account get-access-token in a new CLI process')
            self.assertEqual(token_result.returncode, 0, token_result.stderr)


if __name__ == '__main__':
    unittest.main()
