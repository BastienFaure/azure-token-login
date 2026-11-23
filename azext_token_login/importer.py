"""Import short-lived bearer tokens into the Azure CLI profile and MSAL cache.

This module targets Azure CLI 2.81.0 and MSAL 1.39.0. Their cache schema is an
implementation detail, not an Azure CLI authentication API.
"""

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import azure.cli.core
import msal
from azure.cli.core._environment import get_config_dir
from azure.cli.core.auth.constants import AZURE_CLI_CLIENT_ID
from azure.cli.core.auth.persistence import load_persisted_token_cache
from azure.cli.core.auth.util import resource_to_scopes
from azure.cli.core.util import should_encrypt_token_cache
from knack.util import CLIError
from msal_extensions import CrossPlatLock
from msal_extensions.persistence import PersistenceNotFound

from .token import guid, parse_access_token

PROFILE_FILE = 'azureProfile.json'
STATE_FILE = 'token-login-state.json'
MAX_METADATA_SIZE = 10 * 1024 * 1024


def _check_version():
    if not sys.platform.startswith('linux'):
        raise CLIError('This version of token-login supports Linux only.')
    if (azure.cli.core.__version__ != '2.81.0' or msal.__version__ != '1.39.0'
            or version('msal-extensions') != '1.3.1'):
        raise CLIError('This extension supports only Azure CLI 2.81.0, MSAL 1.39.0, '
                       'and MSAL Extensions 1.3.1. The internal cache schema must '
                       'be retested after an upgrade.')


def _private_directory():
    directory = Path(get_config_dir()).expanduser()
    try:
        info = directory.lstat()
    except FileNotFoundError:
        directory.mkdir(mode=0o700, parents=True)
        info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CLIError('Azure config directory must be owned by you and mode 0700. '
                       'Secure ~/.azure or use a private AZURE_CONFIG_DIR before importing tokens.')
    return directory


def _read_json(path, default):
    if not path.exists() and not path.is_symlink():
        return copy.deepcopy(default)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA_SIZE:
        raise CLIError('Azure CLI metadata must be a regular JSON file of reasonable size.')
    try:
        with path.open('r', encoding='utf-8-sig') as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, ValueError) as exc:
        raise CLIError('Could not read Azure CLI metadata; no files were overwritten.') from exc
    if not isinstance(value, dict):
        raise CLIError('Azure CLI metadata must be a JSON object.')
    return value


def _save_json(path, value):
    fd, temp_name = tempfile.mkstemp(prefix='.token-login-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _state(directory):
    state = _read_json(directory / STATE_FILE, {'version': 1, 'entries': {}})
    if state.get('version') != 1 or not isinstance(state.get('entries'), dict):
        raise CLIError('Unrecognized token-login state; no files were changed.')
    return state


def _profile(directory):
    profile = _read_json(directory / PROFILE_FILE, {'subscriptions': []})
    profile.setdefault('subscriptions', [])
    if not isinstance(profile['subscriptions'], list):
        raise CLIError('Unrecognized Azure CLI subscriptions profile.')
    return profile


def _cache(directory, cli_ctx):
    if should_encrypt_token_cache(cli_ctx):
        raise CLIError('Encrypted Azure CLI token caches are not supported by this extension.')
    cache_file = directory / 'msal_token_cache.json'
    if cache_file.is_symlink() or (cache_file.exists() and not stat.S_ISREG(cache_file.lstat().st_mode)):
        raise CLIError('MSAL token cache must be a regular file, not a symlink.')
    if cache_file.exists() and cache_file.stat().st_mode & 0o077:
        raise CLIError('MSAL token cache must have owner-only file permissions (0600).')
    return load_persisted_token_cache(str(directory / 'msal_token_cache'), encrypt=False)


def _authority(cli_ctx):
    authority = urlparse(cli_ctx.cloud.endpoints.active_directory)
    if authority.scheme != 'https' or not authority.hostname:
        raise CLIError('Unsupported active Azure cloud authority.')
    return authority.hostname.lower()


def _matching_at(cache, entry):
    query = {k: entry[k] for k in ('home_account_id', 'environment', 'client_id', 'realm')}
    tokens = list(cache.search(cache.CredentialType.ACCESS_TOKEN,
                               target=[entry['target']], query=query))
    return tokens


def _find_reusable_account(cache, existing_profile, token, environment, target):
    if not existing_profile or not token.object_id:
        return None
    if existing_profile.get('tenantId', '').lower() != token.tenant_id:
        return None
    user = existing_profile.get('user', {})
    if user.get('type') != 'user':
        return None
    username = user.get('name', '')
    matches = [a for a in cache.search(cache.CredentialType.ACCOUNT,
                                       query={'environment': environment})
               if a.get('username', '').lower() == username.lower()
               and a.get('local_account_id', '').lower() == token.object_id]
    if len(matches) != 1:
        return None
    account = matches[0]
    home = account['home_account_id']
    if list(cache.search(cache.CredentialType.REFRESH_TOKEN,
                         query={'home_account_id': home, 'environment': environment})):
        return None  # No silent refresh through a previously logged-in session.
    candidate = {'home_account_id': home, 'environment': environment,
                 'client_id': AZURE_CLI_CLIENT_ID, 'realm': token.tenant_id,
                 'target': target}
    if _matching_at(cache, candidate):
        return None  # Never replace another login's access token.
    return account


def _new_account(environment, tenant_id):
    identifier = uuid4().hex
    return {'home_account_id': f'{identifier}.{tenant_id}',
            'environment': environment, 'realm': tenant_id,
            'local_account_id': identifier, 'username': f'token-login-{identifier}',
            'authority_type': 'MSSTS', 'account_source': 'token-login'}


def _new_at(token, account, environment, target, now):
    return {'credential_type': 'AccessToken', 'secret': token.token,
            'home_account_id': account['home_account_id'], 'environment': environment,
            'client_id': AZURE_CLI_CLIENT_ID, 'target': target,
            'realm': token.tenant_id, 'token_type': 'Bearer',
            'cached_at': str(now), 'expires_on': str(token.expires_on),
            'extended_expires_on': str(token.expires_on)}


def _record(profile, sub_id, environment_name):
    matches = [s for s in profile['subscriptions']
               if isinstance(s, dict) and s.get('id', '').lower() == sub_id
               and s.get('environmentName') == environment_name]
    if len(matches) > 1:
        raise CLIError('Multiple Azure CLI profile entries have the same subscription ID.')
    return matches[0] if matches else None


def _restore_profile(profile, state_entries, selected):
    subscriptions = profile['subscriptions']
    removed_active_clouds = set()
    for sub_id in selected:
        entry = state_entries[sub_id]
        current = _record(profile, sub_id, entry['cloud'])
        if not _imported_profile_matches(current, entry):
            if not ((entry['pending'] or entry.get('removing'))
                    and _profile_already_restored(current, entry)):
                raise CLIError('An imported profile entry was changed; cannot safely restore it.')
        else:
            default = current.get('isDefault', False)
            if default:
                removed_active_clouds.add(entry['cloud'])
            subscriptions.remove(current)
            previous = entry['previous_profile']
            if previous is not None:
                previous = copy.deepcopy(previous)
                previous['isDefault'] = bool(default and previous.get('isDefault'))
                subscriptions.append(previous)
    for name in removed_active_clouds:
        cloud_subs = [s for s in subscriptions if s.get('environmentName') == name]
        if cloud_subs and not any(s.get('isDefault') for s in cloud_subs):
            for sub_id in selected:
                prior_default = state_entries[sub_id].get('previous_default')
                match = next((s for s in cloud_subs if s.get('id') == prior_default), None)
                if match:
                    match['isDefault'] = True
                    break
    return profile


def _assert_removable(cache, profile, state_entries, selected):
    for sub_id in selected:
        entry = state_entries[sub_id]
        current = _record(profile, sub_id, entry['cloud'])
        if not _imported_profile_matches(current, entry):
            if not ((entry['pending'] or entry.get('removing'))
                    and _profile_already_restored(current, entry)):
                raise CLIError('An imported subscription was changed; refusing to overwrite it.')
        tokens = _matching_at(cache, entry)
        if len(tokens) > 1 or (tokens and hashlib.sha256(tokens[0]['secret'].encode()).hexdigest()
                                   != entry['token_sha256']):
            raise CLIError('A cached token was changed by another process; refusing to remove it.')
        if entry['created_account']:
            home = {'home_account_id': entry['home_account_id'],
                    'environment': entry['environment']}
            other_tokens = [at for at in cache.search(cache.CredentialType.ACCESS_TOKEN,
                                                      query=home) if at not in tokens]
            other_tokens += list(cache.search(cache.CredentialType.REFRESH_TOKEN, query=home))
            other_tokens += list(cache.search(cache.CredentialType.ID_TOKEN, query=home))
            if other_tokens:
                raise CLIError('Another credential now uses the imported account; refusing to remove it.')


def _save_profile_if_current(directory, expected, replacement):
    # Ordinary az commands do not honor our lock. Detect a changed profile
    # before replacing it; callers must still keep other az processes idle.
    if _profile(directory) != expected:
        raise CLIError('Azure CLI profile changed during the operation; refusing to overwrite it.')
    _save_json(directory / PROFILE_FILE, replacement)


def _profile_already_restored(current, entry):
    previous = entry['previous_profile']
    if current is None or previous is None:
        return current is None and previous is None
    # `az account set` is permitted to change only the default selection.
    return {k: v for k, v in current.items() if k != 'isDefault'} == {
        k: v for k, v in previous.items() if k != 'isDefault'}


def _imported_profile_matches(current, entry):
    expected = entry['imported_profile']
    return current is not None and {k: v for k, v in current.items() if k != 'isDefault'} == {
        k: v for k, v in expected.items() if k != 'isDefault'}


def _load_cache_snapshot(cache):
    snapshot = msal.SerializableTokenCache()
    try:
        snapshot.deserialize(cache._persistence.load())  # pylint: disable=protected-access
    except PersistenceNotFound:
        pass  # A fresh Azure configuration has no cache file yet.
    return snapshot


def _save_cache_snapshot(cache, snapshot):
    serialized = snapshot.serialize()
    cache._persistence.save(serialized)  # pylint: disable=protected-access
    cache.deserialize(serialized)
    cache._last_sync = time.time()  # pylint: disable=protected-access


def _add_cache_entries(cache, account, at, created):
    with CrossPlatLock(cache._lock_location):  # pylint: disable=protected-access
        snapshot = _load_cache_snapshot(cache)
        at_key = snapshot.key_makers[snapshot.CredentialType.ACCESS_TOKEN](**at)
        if snapshot._get(snapshot.CredentialType.ACCESS_TOKEN, at_key):  # pylint: disable=protected-access
            raise CLIError('An access token was added concurrently; refusing to replace it.')
        account_key = snapshot.key_makers[snapshot.CredentialType.ACCOUNT](**account)
        existing = snapshot._get(snapshot.CredentialType.ACCOUNT, account_key)  # pylint: disable=protected-access
        if created and existing:
            raise CLIError('A new account was added concurrently; refusing to replace it.')
        if not created and existing != account:
            raise CLIError('The existing MSAL account changed during import.')
        if created:
            snapshot.modify(snapshot.CredentialType.ACCOUNT, account, account)
        snapshot.modify(snapshot.CredentialType.ACCESS_TOKEN, at, at)
        _save_cache_snapshot(cache, snapshot)


def _remove_cache_entries(cache, entry):
    # MSAL's PersistedTokenCache locks each modify() separately. Hold its
    # shared lock over the last read, comparison, and deletion as one unit.
    with CrossPlatLock(cache._lock_location):  # pylint: disable=protected-access
        snapshot = _load_cache_snapshot(cache)
        key = snapshot.key_makers[snapshot.CredentialType.ACCESS_TOKEN](**entry)
        token = snapshot._get(snapshot.CredentialType.ACCESS_TOKEN, key)  # pylint: disable=protected-access
        if token and hashlib.sha256(token['secret'].encode()).hexdigest() != entry['token_sha256']:
            raise CLIError('A cached token changed during removal; refusing to delete it.')
        if entry['created_account']:
            for kind in (snapshot.CredentialType.ACCESS_TOKEN,
                         snapshot.CredentialType.REFRESH_TOKEN,
                         snapshot.CredentialType.ID_TOKEN):
                for other in snapshot._cache.get(kind, {}).values():  # pylint: disable=protected-access
                    if (other.get('home_account_id') == entry['home_account_id']
                            and other.get('environment') == entry['environment']
                            and other is not token):
                        raise CLIError('Another credential now uses this account; refusing to remove it.')
        if token:
            snapshot.remove_at(token)
        if entry['created_account']:
            key = snapshot.key_makers[snapshot.CredentialType.ACCOUNT](**entry)
            account = snapshot._get(snapshot.CredentialType.ACCOUNT, key)  # pylint: disable=protected-access
            if account and account.get('username') != entry['username']:
                raise CLIError('The imported account was changed; refusing to remove it.')
            if account:
                snapshot.remove_account(account)
        if snapshot.has_state_changed:
            _save_cache_snapshot(cache, snapshot)


def _remove_locked(directory, cli_ctx, state, selected):
    profile = _profile(directory)
    cache = _cache(directory, cli_ctx)
    entries = state['entries']
    _assert_removable(cache, profile, entries, selected)
    restored = _restore_profile(copy.deepcopy(profile), entries, selected)
    for sub_id in selected:
        entries[sub_id]['removing'] = True
    _save_json(directory / STATE_FILE, state)  # Removal journal survives a failed final save.
    for sub_id in selected:
        _remove_cache_entries(cache, entries[sub_id])
    _save_profile_if_current(directory, profile, restored)
    for sub_id in selected:
        del entries[sub_id]
    _save_json(directory / STATE_FILE, state)


def import_access_token(cli_ctx, access_token, subscription_id):
    _check_version()
    source = parse_access_token(access_token, subscription_id,
                                cli_ctx.cloud.endpoints.active_directory_resource_id)
    config_dir = _private_directory()
    with CrossPlatLock(str(config_dir / '.token-login.lock')):
        profile = _profile(config_dir)
        state = _state(config_dir)
        cache = _cache(config_dir, cli_ctx)
        sub_id = source.subscription_id
        if sub_id in state['entries']:
            raise CLIError('This subscription is already imported; remove its import before replacing it.')
        now = int(time.time())
        if source.expires_on - now <= 300:
            raise CLIError('The access token expired while preparing the import; obtain a new token.')
        authority = _authority(cli_ctx)
        scope = resource_to_scopes(cli_ctx.cloud.endpoints.active_directory_resource_id)[0]
        prior = _record(profile, sub_id, cli_ctx.cloud.name)
        account = _find_reusable_account(cache, prior, source, authority, scope)
        created = account is None
        if created:
            account = _new_account(authority, source.tenant_id)
        at = _new_at(source, account, authority, scope, now)
        if _matching_at(cache, at):
            raise CLIError('An access token already exists for the chosen MSAL account.')
        pre_default = next((s.get('id') for s in profile['subscriptions']
                            if s.get('environmentName') == cli_ctx.cloud.name
                            and s.get('isDefault')), None)
        new_sub = copy.deepcopy(prior) if prior else {}
        new_sub.update({'id': sub_id, 'name': (prior or {}).get('name', sub_id),
                        'state': 'Enabled', 'environmentName': cli_ctx.cloud.name,
                        'tenantId': source.tenant_id,
                        'user': {'name': account['username'], 'type': 'user'},
                        'isDefault': (prior or {}).get('isDefault', False) or pre_default is None})
        updated = copy.deepcopy(profile)
        if prior:
            updated['subscriptions'].remove(prior)
        updated['subscriptions'].append(new_sub)
        state['entries'][sub_id] = {'cloud': cli_ctx.cloud.name, 'previous_profile': prior,
                                    'imported_profile': copy.deepcopy(new_sub),
                                    'previous_default': pre_default,
                                    'username': account['username'], 'created_account': created,
                                    'home_account_id': account['home_account_id'],
                                    'environment': authority, 'realm': source.tenant_id,
                                    'client_id': AZURE_CLI_CLIENT_ID, 'target': scope,
                                    'token_sha256': hashlib.sha256(source.token.encode()).hexdigest(),
                                    'pending': True}
        _save_json(config_dir / STATE_FILE, state)  # Recovery journal precedes credential writes.
        try:
            _add_cache_entries(cache, account, at, created)
            _save_profile_if_current(config_dir, profile, updated)
            state['entries'][sub_id]['pending'] = False
            _save_json(config_dir / STATE_FILE, state)
        except Exception:
            try:
                _remove_locked(config_dir, cli_ctx, state, [sub_id])
            except Exception:
                raise CLIError('Import failed; run `az token-login remove` to recover pending changes.') from None
            raise CLIError('Import failed; pending changes were rolled back.') from None


def remove_files(cli_ctx, subscription_id=None):
    _check_version()
    config_dir = _private_directory()
    with CrossPlatLock(str(config_dir / '.token-login.lock')):
        state = _state(config_dir)
        if subscription_id:
            subscription_id = guid(subscription_id, 'Subscription ID')
            if subscription_id not in state['entries']:
                raise CLIError('No import is recorded for that subscription.')
            selected = [subscription_id]
        else:
            selected = list(state['entries'])
        if selected:
            _remove_locked(config_dir, cli_ctx, state, selected)
    return len(selected)
