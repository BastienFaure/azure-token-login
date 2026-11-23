"""Offline tests: every token and cache entry in this file is fabricated."""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azure.cli.core.auth.constants import AZURE_CLI_CLIENT_ID
from azure.cli.core.auth.msal_credentials import UserCredential
from azure.cli.core.auth.persistence import load_persisted_token_cache
from knack.util import CLIError

from azext_token_login import importer
from azext_token_login.token import parse_access_token

TENANT = '11111111-1111-4111-8111-111111111111'
SECOND_TENANT = '22222222-2222-4222-8222-222222222222'
SUB = '33333333-3333-4333-8333-333333333333'
OTHER_SUB = '44444444-4444-4444-8444-444444444444'
OID = '55555555-5555-4555-8555-555555555555'
ARM = 'https://management.core.windows.net/'
AUTHORITY = 'login.microsoftonline.com'
SCOPE = ARM + '/.default'


def jwt(tenant=TENANT, audience=ARM, expires=None, oid=OID):
    expires = int(time.time()) + 3600 if expires is None else expires
    header = {'alg': 'RS256', 'typ': 'JWT'}
    claims = {'tid': tenant, 'oid': oid, 'aud': audience, 'exp': expires,
              'appid': AZURE_CLI_CLIENT_ID}

    def encoded(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')

    return f'{encoded(header)}.{encoded(claims)}.fabricated-signature'


class Config:
    def getboolean(self, section, key, fallback=False):
        return fallback


class TokenLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config_dir = Path(self.temp.name) / 'azure'
        self.config_dir.mkdir(mode=0o700)
        self.env = mock.patch.dict(os.environ, {'AZURE_CONFIG_DIR': str(self.config_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.cli_ctx = SimpleNamespace(cloud=SimpleNamespace(
            name='AzureCloud', endpoints=SimpleNamespace(
                active_directory='https://login.microsoftonline.com/',
                active_directory_resource_id=ARM)),
            config=Config())

    def profile(self):
        return importer._profile(self.config_dir)

    def cache(self):
        return load_persisted_token_cache(str(self.config_dir / 'msal_token_cache'), False)

    def test_import_and_remove_preserve_unrelated_default(self):
        unrelated = {'id': OTHER_SUB, 'name': 'Unrelated', 'tenantId': TENANT,
                     'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
                     'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [unrelated]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        self.assertEqual(len(profile['subscriptions']), 2)
        self.assertEqual(importer._record(profile, OTHER_SUB, 'AzureCloud'), unrelated)
        imported = importer._record(profile, SUB, 'AzureCloud')
        self.assertFalse(imported['isDefault'])
        self.assertTrue(imported['user']['name'].startswith('token-login-'))
        cache = self.cache()
        ats = list(cache.search(cache.CredentialType.ACCESS_TOKEN))
        self.assertEqual(len(ats), 1)
        self.assertEqual(ats[0]['target'], SCOPE)
        self.assertEqual(ats[0]['realm'], TENANT)
        self.assertEqual(list(cache.search(cache.CredentialType.REFRESH_TOKEN)), [])
        self.assertEqual(importer.remove_files(self.cli_ctx), 1)
        self.assertEqual(self.profile()['subscriptions'], [unrelated])
        self.assertFalse(list(self.cache().search(cache.CredentialType.ACCOUNT)))

    def test_replacing_existing_subscription_restores_its_profile(self):
        old = {'id': SUB, 'name': 'Old name', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        current = importer._record(self.profile(), SUB, 'AzureCloud')
        self.assertNotEqual(current['user'], old['user'])
        self.assertTrue(current['isDefault'])
        importer.remove_files(self.cli_ctx, SUB)
        self.assertEqual(self.profile()['subscriptions'], [old])

    def test_reuse_existing_account_only_without_refresh_or_access_token(self):
        old = {'id': SUB, 'name': 'Old name', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        account = {'home_account_id': OID + '.' + TENANT,
                   'environment': AUTHORITY, 'realm': TENANT,
                   'local_account_id': OID, 'username': old['user']['name'],
                   'authority_type': 'MSSTS'}
        cache = self.cache()
        cache.modify(cache.CredentialType.ACCOUNT, account, account)
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        state = importer._state(self.config_dir)['entries'][SUB]
        self.assertFalse(state['created_account'])
        self.assertEqual(state['home_account_id'], account['home_account_id'])
        importer.remove_files(self.cli_ctx)
        self.assertEqual(list(self.cache().search(cache.CredentialType.ACCOUNT)), [account])

    def test_reused_account_rechecks_refresh_token_under_cache_lock(self):
        old = {'id': SUB, 'name': 'Old name', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        account = {'home_account_id': OID + '.' + TENANT,
                   'environment': AUTHORITY, 'realm': TENANT,
                   'local_account_id': OID, 'username': old['user']['name'],
                   'authority_type': 'MSSTS'}
        cache = self.cache()
        cache.modify(cache.CredentialType.ACCOUNT, account, account)
        original_add = importer._add_cache_entries

        def add_refresh_before_token(target_cache, selected_account, at, created):
            refresh = {'credential_type': 'RefreshToken', 'secret': 'fabricated-refresh',
                       'home_account_id': account['home_account_id'],
                       'environment': AUTHORITY, 'client_id': AZURE_CLI_CLIENT_ID,
                       'target': SCOPE}
            other = self.cache()
            other.modify(other.CredentialType.REFRESH_TOKEN, refresh, refresh)
            return original_add(target_cache, selected_account, at, created)

        with mock.patch.object(importer, '_add_cache_entries', side_effect=add_refresh_before_token):
            with self.assertRaisesRegex(CLIError, 'rolled back'):
                importer.import_access_token(self.cli_ctx, jwt(), SUB)
        self.assertEqual(self.profile()['subscriptions'], [old])
        self.assertFalse(list(self.cache().search('AccessToken')))
        self.assertEqual(len(list(self.cache().search('RefreshToken'))), 1)

    def test_existing_refresh_token_is_preserved_and_not_borrowed(self):
        old = {'id': SUB, 'name': 'Old name', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        account = {'home_account_id': OID + '.' + TENANT,
                   'environment': AUTHORITY, 'realm': TENANT,
                   'local_account_id': OID, 'username': old['user']['name'],
                   'authority_type': 'MSSTS'}
        refresh = {'credential_type': 'RefreshToken', 'secret': 'fabricated-refresh',
                   'home_account_id': account['home_account_id'],
                   'environment': AUTHORITY, 'client_id': AZURE_CLI_CLIENT_ID,
                   'target': SCOPE}
        cache = self.cache()
        cache.modify(cache.CredentialType.ACCOUNT, account, account)
        cache.modify(cache.CredentialType.REFRESH_TOKEN, refresh, refresh)
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        record = importer._state(self.config_dir)['entries'][SUB]
        self.assertTrue(record['created_account'])
        self.assertNotEqual(record['home_account_id'], account['home_account_id'])
        importer.remove_files(self.cli_ctx)
        self.assertEqual(list(self.cache().search(cache.CredentialType.REFRESH_TOKEN)), [refresh])
        self.assertEqual(self.profile()['subscriptions'], [old])

    def test_sequential_tenants_use_separate_accounts_and_realms(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        importer.import_access_token(self.cli_ctx, jwt(tenant=SECOND_TENANT), OTHER_SUB)
        self.assertEqual({s['tenantId'] for s in self.profile()['subscriptions']},
                         {TENANT, SECOND_TENANT})
        self.assertEqual({a['realm'] for a in self.cache().search('AccessToken')},
                         {TENANT, SECOND_TENANT})
        importer.remove_files(self.cli_ctx)

    def test_msal_user_credential_retrieves_imported_token_offline(self):
        fabricated = jwt()
        importer.import_access_token(self.cli_ctx, fabricated, SUB)
        username = importer._record(self.profile(), SUB, 'AzureCloud')['user']['name']
        discovery = {'authorization_endpoint': f'https://{AUTHORITY}/{TENANT}/oauth2/v2.0/authorize',
                     'token_endpoint': f'https://{AUTHORITY}/{TENANT}/oauth2/v2.0/token',
                     'issuer': f'https://{AUTHORITY}/{TENANT}/v2.0'}
        with mock.patch('msal.authority.tenant_discovery', return_value=discovery), \
             mock.patch('requests.Session.get', side_effect=AssertionError('Unexpected network call')):
            credential = UserCredential(AZURE_CLI_CLIENT_ID, username,
                                        authority=f'https://{AUTHORITY}/{TENANT}',
                                        token_cache=self.cache(), instance_discovery=False)
            self.assertEqual(credential.acquire_token([SCOPE])['access_token'], fabricated)

    def test_graph_audience_is_rejected_for_arm_import(self):
        graph_token = jwt(audience='https://graph.microsoft.com/')
        with self.assertRaisesRegex(CLIError, 'audience.*ARM'):
            importer.import_access_token(self.cli_ctx, graph_token, SUB)
        self.assertFalse((self.config_dir / importer.STATE_FILE).exists())

    def test_expiring_token_does_not_write_state(self):
        with self.assertRaisesRegex(CLIError, 'expires'):
            importer.import_access_token(self.cli_ctx,
                                         jwt(expires=int(time.time()) + 100), SUB)
        self.assertFalse((self.config_dir / importer.STATE_FILE).exists())

    def test_access_token_requires_explicit_subscription_guid(self):
        parsed = parse_access_token(jwt(), SUB, ARM)
        self.assertEqual(parsed.subscription_id, SUB)
        self.assertEqual(parsed.tenant_id, TENANT)
        with self.assertRaisesRegex(CLIError, 'Subscription ID must be a GUID'):
            importer.import_access_token(self.cli_ctx, jwt(), 'not-a-guid')
        self.assertFalse((self.config_dir / importer.STATE_FILE).exists())

    def test_json_wrapper_is_rejected_without_echoing_value(self):
        wrapper = json.dumps({'token': jwt(), 'subscription_name': 'Example'})
        with self.assertRaises(CLIError) as raised:
            importer.import_access_token(self.cli_ctx, wrapper, SUB)
        self.assertNotIn(wrapper, str(raised.exception))
        self.assertFalse((self.config_dir / importer.STATE_FILE).exists())

    def test_second_import_for_same_subscription_is_rejected(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        with self.assertRaisesRegex(CLIError, 'already imported'):
            importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB)
        self.assertEqual(len(list(self.cache().search('AccessToken'))), 1)
        importer.remove_files(self.cli_ctx)

    def test_force_replaces_token_and_restores_original_association(self):
        old = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        original = jwt()
        replacement = jwt(tenant=SECOND_TENANT)
        importer.import_access_token(self.cli_ctx, original, SUB)
        importer.import_access_token(self.cli_ctx, replacement, SUB, force=True)
        self.assertEqual([a['secret'] for a in self.cache().search('AccessToken')], [replacement])
        self.assertEqual(importer._state(self.config_dir)['entries'][SUB]['previous_profile'], old)
        importer.import_access_token(self.cli_ctx, jwt(), SUB, force=True)
        importer.remove_files(self.cli_ctx, SUB)
        self.assertEqual(self.profile()['subscriptions'], [old])
        self.assertFalse(list(self.cache().search('AccessToken')))

    def test_replacement_preserves_active_subscription(self):
        unrelated = {'id': OTHER_SUB, 'name': 'Unrelated', 'tenantId': TENANT,
                     'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
                     'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({
            'subscriptions': [unrelated]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        importer._record(profile, OTHER_SUB, 'AzureCloud')['isDefault'] = False
        importer._record(profile, SUB, 'AzureCloud')['isDefault'] = True
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        profile = self.profile()
        self.assertTrue(importer._record(profile, SUB, 'AzureCloud')['isDefault'])
        self.assertFalse(importer._record(profile, OTHER_SUB, 'AzureCloud')['isDefault'])
        importer.remove_files(self.cli_ctx, SUB)
        self.assertTrue(importer._record(self.profile(), OTHER_SUB, 'AzureCloud')['isDefault'])

    def test_replacement_preserves_new_subscription_metadata(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        profile['subscriptions'][0].update(name='Friendly subscription', state='Disabled',
                                           tenantDisplayName='Updated tenant')
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        imported = importer._record(self.profile(), SUB, 'AzureCloud')
        self.assertEqual(imported['name'], 'Friendly subscription')
        self.assertEqual(imported['state'], 'Disabled')
        self.assertEqual(imported['tenantDisplayName'], 'Updated tenant')
        importer.remove_files(self.cli_ctx, SUB)

    def test_replacement_restores_old_token_if_new_one_expires_midway(self):
        now = int(time.time())
        original = jwt(expires=now + 3600)
        importer.import_access_token(self.cli_ctx, original, SUB)
        original_remove = importer._remove_locked
        clock = {'now': now}

        def remove_then_advance(*args, **kwargs):
            result = original_remove(*args, **kwargs)
            clock['now'] += 1
            return result

        with mock.patch.object(importer.time, 'time', side_effect=lambda: clock['now']), \
             mock.patch.object(importer, '_remove_locked', side_effect=remove_then_advance):
            with self.assertRaisesRegex(CLIError, 'previous import was restored'):
                importer.import_access_token(self.cli_ctx, jwt(expires=now + 301),
                                             SUB, force=True)
        self.assertEqual([a['secret'] for a in self.cache().search('AccessToken')], [original])
        self.assertIn(SUB, importer._state(self.config_dir)['entries'])
        importer.remove_files(self.cli_ctx, SUB)

    def test_removal_accepts_case_only_subscription_id_change(self):
        subscription = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        importer.import_access_token(self.cli_ctx, jwt(), subscription)
        profile = self.profile()
        profile['subscriptions'][0]['id'] = subscription.upper()
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        self.assertEqual(importer.remove_files(self.cli_ctx, subscription), 1)
        self.assertEqual(self.profile()['subscriptions'], [])
        self.assertFalse(list(self.cache().search('AccessToken')))

    def test_replacement_preserves_original_disabled_state(self):
        old = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Disabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        importer.remove_files(self.cli_ctx, SUB)
        self.assertEqual(self.profile()['subscriptions'], [old])

    def test_replacement_carries_profile_metadata_changes(self):
        old = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        profile['subscriptions'][0]['state'] = 'Disabled'
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        importer.remove_files(self.cli_ctx, SUB)
        self.assertEqual(self.profile()['subscriptions'][0]['state'], 'Disabled')

    def test_expired_token_is_replaced_without_force(self):
        now = int(time.time())
        importer.import_access_token(self.cli_ctx, jwt(expires=now + 3600), SUB)
        replacement = jwt(expires=now + 7200)
        with mock.patch.object(importer.time, 'time', return_value=now + 3600):
            importer.import_access_token(self.cli_ctx, replacement, SUB)
        self.assertEqual([a['secret'] for a in self.cache().search('AccessToken')], [replacement])
        importer.remove_files(self.cli_ctx, SUB)

    def test_unexpired_token_requires_force_even_near_expiry(self):
        now = int(time.time())
        importer.import_access_token(self.cli_ctx, jwt(expires=now + 3600), SUB)
        with mock.patch.object(importer.time, 'time', return_value=now + 3599):
            with self.assertRaisesRegex(CLIError, 'already imported'):
                importer.import_access_token(self.cli_ctx, jwt(expires=now + 7200), SUB)
        importer.remove_files(self.cli_ctx, SUB)

    def test_expired_legacy_state_reads_exact_cached_token(self):
        now = int(time.time())
        importer.import_access_token(self.cli_ctx, jwt(expires=now + 3600), SUB)
        state = importer._state(self.config_dir)
        del state['entries'][SUB]['expires_on']
        importer._save_json(self.config_dir / importer.STATE_FILE, state)
        replacement = jwt(expires=now + 7200)
        with mock.patch.object(importer.time, 'time', return_value=now + 3600):
            importer.import_access_token(self.cli_ctx, replacement, SUB)
        self.assertEqual([a['secret'] for a in self.cache().search('AccessToken')], [replacement])
        importer.remove_files(self.cli_ctx, SUB)

    def test_missing_legacy_token_requires_force(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        state = importer._state(self.config_dir)
        del state['entries'][SUB]['expires_on']
        importer._save_json(self.config_dir / importer.STATE_FILE, state)
        cache = self.cache()
        cache.remove_at(next(iter(cache.search('AccessToken'))))
        with self.assertRaisesRegex(CLIError, 'already imported'):
            importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB)
        importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        importer.remove_files(self.cli_ctx, SUB)

    def test_expired_record_with_missing_token_can_be_replaced(self):
        now = int(time.time())
        importer.import_access_token(self.cli_ctx, jwt(expires=now + 3600), SUB)
        cache = self.cache()
        cache.remove_at(next(iter(cache.search('AccessToken'))))
        replacement = jwt(expires=now + 7200)
        with mock.patch.object(importer.time, 'time', return_value=now + 3600):
            importer.import_access_token(self.cli_ctx, replacement, SUB)
        self.assertEqual([a['secret'] for a in self.cache().search('AccessToken')], [replacement])
        importer.remove_files(self.cli_ctx, SUB)

    def test_expired_changed_token_is_not_replaced(self):
        now = int(time.time())
        importer.import_access_token(self.cli_ctx, jwt(expires=now + 3600), SUB)
        cache = self.cache()
        original = next(iter(cache.search('AccessToken')))
        cache.modify(cache.CredentialType.ACCESS_TOKEN, original,
                     {'secret': jwt(oid=OTHER_SUB, expires=now + 7200)})
        with mock.patch.object(importer.time, 'time', return_value=now + 3600):
            with self.assertRaisesRegex(CLIError, 'cached token'):
                importer.import_access_token(self.cli_ctx, jwt(expires=now + 7200), SUB)
        self.assertIn(SUB, importer._state(self.config_dir)['entries'])

    def test_force_does_not_replace_changed_cached_token(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        cache = self.cache()
        original = next(iter(cache.search('AccessToken')))
        replacement = jwt(oid=OTHER_SUB)
        cache.modify(cache.CredentialType.ACCESS_TOKEN, original, {'secret': replacement})
        with self.assertRaisesRegex(CLIError, 'cached token'):
            importer.import_access_token(self.cli_ctx, jwt(tenant=SECOND_TENANT), SUB, force=True)
        self.assertIn(SUB, importer._state(self.config_dir)['entries'])
        self.assertEqual(next(iter(self.cache().search('AccessToken')))['secret'], replacement)

    def test_replacement_does_not_take_over_changed_profile(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        profile['subscriptions'][0]['user']['name'] = 'different@example.invalid'
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        with self.assertRaisesRegex(CLIError, 'another login'):
            importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        self.assertEqual(self.profile(), profile)
        self.assertIn(SUB, importer._state(self.config_dir)['entries'])
        self.assertEqual(importer.remove_files(self.cli_ctx, SUB), 1)
        self.assertEqual(self.profile(), profile)
        self.assertFalse(list(self.cache().search('AccessToken')))

    def test_extra_user_metadata_does_not_block_removal(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        profile['subscriptions'][0]['user']['displayName'] = 'Updated name'
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        self.assertEqual(importer.remove_files(self.cli_ctx, SUB), 1)
        self.assertEqual(self.profile()['subscriptions'], [])

    def test_removal_leaves_external_profile_replacement_intact(self):
        old = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        replacement = dict(old, user={'name': 'new@example.invalid', 'type': 'user'})
        importer._save_json(self.config_dir / importer.PROFILE_FILE,
                            {'subscriptions': [replacement]})
        self.assertEqual(importer.remove_files(self.cli_ctx, SUB), 1)
        self.assertEqual(self.profile()['subscriptions'], [replacement])
        self.assertFalse(list(self.cache().search('AccessToken')))

    def test_missing_profile_record_does_not_block_removal(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        importer._save_json(self.config_dir / importer.PROFILE_FILE, {'subscriptions': []})
        self.assertEqual(importer.remove_files(self.cli_ctx, SUB), 1)
        self.assertEqual(self.profile()['subscriptions'], [])
        self.assertFalse(importer._state(self.config_dir)['entries'])

    def test_pending_import_cannot_be_replaced(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        state = importer._state(self.config_dir)
        state['entries'][SUB]['pending'] = True
        importer._save_json(self.config_dir / importer.STATE_FILE, state)
        with self.assertRaisesRegex(CLIError, 'unfinished'):
            importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        importer.remove_files(self.cli_ctx, SUB)

    def test_failed_replacement_restores_previous_profile(self):
        old = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        original_token = jwt()
        importer.import_access_token(self.cli_ctx, original_token, SUB)
        original_save = importer._save_json
        failure = {'once': True}

        def fail_new_profile(path, value):
            if (path.name == importer.PROFILE_FILE and failure['once']
                    and importer._record(value, SUB, 'AzureCloud')['user']['name'] != old['user']['name']):
                failure['once'] = False
                raise OSError('simulated replacement failure')
            return original_save(path, value)

        with mock.patch.object(importer, '_save_json', side_effect=fail_new_profile):
            with self.assertRaisesRegex(CLIError, 'Replacement failed'):
                importer.import_access_token(self.cli_ctx, jwt(oid=OTHER_SUB), SUB, force=True)
        self.assertEqual(importer._state(self.config_dir)['entries'][SUB]['previous_profile'], old)
        self.assertNotEqual(self.profile()['subscriptions'], [old])
        self.assertEqual([a['secret'] for a in self.cache().search('AccessToken')],
                         [original_token])
        importer.remove_files(self.cli_ctx, SUB)
        self.assertEqual(self.profile()['subscriptions'], [old])

    def test_changed_cache_entry_is_not_deleted(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        cache = self.cache()
        entry = next(iter(cache.search('AccessToken')))
        cache.modify(cache.CredentialType.ACCESS_TOKEN, entry, {'secret': jwt(oid=OTHER_SUB)})
        with self.assertRaises(CLIError):
            importer.remove_files(self.cli_ctx)
        self.assertIn(SUB, importer._state(self.config_dir)['entries'])

    def test_failure_rolls_back_profile_and_cache(self):
        original_save = importer._save_json
        once = {'fail': True}

        def save(path, value):
            if path.name == importer.PROFILE_FILE and once['fail']:
                once['fail'] = False
                raise OSError('simulated write failure')
            return original_save(path, value)

        with mock.patch.object(importer, '_save_json', side_effect=save):
            with self.assertRaisesRegex(CLIError, 'rolled back'):
                importer.import_access_token(self.cli_ctx, jwt(), SUB)
        self.assertFalse(importer._state(self.config_dir)['entries'])
        self.assertFalse(list(self.cache().search('AccessToken')))

    def test_removal_preserves_cross_cloud_default_change(self):
        original = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
                    'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
                    'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        other = {'id': OTHER_SUB, 'name': 'Other cloud', 'tenantId': SECOND_TENANT,
                 'environmentName': 'AzureUSGovernment', 'state': 'Enabled', 'isDefault': False,
                 'user': {'name': 'another@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({
            'subscriptions': [original, other]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        importer._record(profile, SUB, 'AzureCloud')['isDefault'] = False
        importer._record(profile, OTHER_SUB, 'AzureUSGovernment')['isDefault'] = True
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        importer.remove_files(self.cli_ctx)
        result = self.profile()
        self.assertFalse(importer._record(result, SUB, 'AzureCloud')['isDefault'])
        self.assertTrue(importer._record(result, OTHER_SUB, 'AzureUSGovernment')['isDefault'])

    def test_removal_rechecks_token_under_msal_lock(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        original_check = importer._assert_removable
        replacement = jwt(oid=OTHER_SUB)

        def changed_after_check(cache, profile, entries, selected):
            original_check(cache, profile, entries, selected)
            other_cache = self.cache()
            current = next(iter(other_cache.search('AccessToken')))
            other_cache.modify(other_cache.CredentialType.ACCESS_TOKEN,
                               current, {'secret': replacement})

        with mock.patch.object(importer, '_assert_removable', side_effect=changed_after_check):
            with self.assertRaisesRegex(CLIError, 'changed during removal'):
                importer.remove_files(self.cli_ctx)
        self.assertEqual(next(iter(self.cache().search('AccessToken')))['secret'], replacement)
        self.assertIn(SUB, importer._state(self.config_dir)['entries'])

    def test_failed_final_state_write_can_be_retried(self):
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        original_save = importer._save_json
        state_saves = {'count': 0}

        def fail_after_restore(path, value):
            if path.name == importer.STATE_FILE:
                state_saves['count'] += 1
                if state_saves['count'] == 2:
                    raise OSError('simulated final state-write failure')
            return original_save(path, value)

        with mock.patch.object(importer, '_save_json', side_effect=fail_after_restore):
            with self.assertRaises(OSError):
                importer.remove_files(self.cli_ctx)
        self.assertEqual(self.profile()['subscriptions'], [])
        self.assertTrue(importer._state(self.config_dir)['entries'][SUB]['removing'])
        self.assertEqual(importer.remove_files(self.cli_ctx), 1)
        self.assertFalse(importer._state(self.config_dir)['entries'])
        self.assertEqual(self.profile()['subscriptions'], [])

    def test_removal_does_not_promote_previously_nondefault_subscription(self):
        unrelated = {'id': OTHER_SUB, 'name': 'Unrelated', 'tenantId': TENANT,
                     'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': False,
                     'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [unrelated]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        self.assertTrue(importer._record(self.profile(), SUB, 'AzureCloud')['isDefault'])
        importer.remove_files(self.cli_ctx)
        self.assertEqual(self.profile()['subscriptions'], [unrelated])

    def test_changed_imported_profile_metadata_is_preserved_on_removal(self):
        old = {'id': SUB, 'name': 'Original', 'tenantId': TENANT,
               'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': True,
               'user': {'name': 'existing@example.invalid', 'type': 'user'}}
        (self.config_dir / 'azureProfile.json').write_text(json.dumps({'subscriptions': [old]}))
        importer.import_access_token(self.cli_ctx, jwt(), SUB)
        profile = self.profile()
        profile['subscriptions'][0].update(name='Updated', state='Disabled',
                                           tenantDisplayName='Updated tenant')
        importer._save_json(self.config_dir / importer.PROFILE_FILE, profile)
        self.assertEqual(importer.remove_files(self.cli_ctx, SUB), 1)
        restored, = self.profile()['subscriptions']
        self.assertEqual(restored['user'], old['user'])
        self.assertEqual(restored['name'], 'Updated')
        self.assertEqual(restored['state'], 'Disabled')
        self.assertEqual(restored['tenantDisplayName'], 'Updated tenant')

    def test_concurrent_profile_change_aborts_import_without_discarding_it(self):
        extra = {'id': OTHER_SUB, 'name': 'Concurrent entry', 'tenantId': TENANT,
                 'environmentName': 'AzureCloud', 'state': 'Enabled', 'isDefault': False,
                 'user': {'name': 'other@example.invalid', 'type': 'user'}}
        original_save = importer._save_profile_if_current
        once = {'change': True}

        def change_before_save(directory, expected, replacement):
            if once['change']:
                once['change'] = False
                profile = importer._profile(directory)
                profile['subscriptions'].append(extra)
                importer._save_json(directory / importer.PROFILE_FILE, profile)
            return original_save(directory, expected, replacement)

        with mock.patch.object(importer, '_save_profile_if_current', side_effect=change_before_save):
            with self.assertRaisesRegex(CLIError, 'rolled back'):
                importer.import_access_token(self.cli_ctx, jwt(), SUB)
        self.assertEqual(self.profile()['subscriptions'], [extra])
        self.assertFalse(importer._state(self.config_dir)['entries'])

    def test_private_config_directory_required(self):
        self.config_dir.chmod(0o777)
        self.addCleanup(lambda: self.config_dir.chmod(0o700))
        with self.assertRaisesRegex(CLIError, 'mode 0700'):
            importer.import_access_token(self.cli_ctx, jwt(), SUB)


if __name__ == '__main__':
    unittest.main()
