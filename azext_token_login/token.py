"""Validate an ARM access token without logging or verifying its JWT signature."""

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import urlparse
from uuid import UUID

from knack.util import CLIError

MAX_TOKEN_LENGTH = 128 * 1024
MIN_LIFETIME = 300  # MSAL attempts refresh when fewer than five minutes remain.


@dataclass(frozen=True)
class AccessToken:
    token: str
    subscription_id: str
    tenant_id: str
    expires_on: int
    object_id: str | None


def guid(value, field):
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise CLIError(f'{field} must be a GUID.') from exc


def _claims(token):
    parts = token.split('.')
    if len(parts) != 3 or not all(re.fullmatch(r'[A-Za-z0-9_-]+', part) for part in parts):
        raise CLIError('The access token must be a three-part JWT.')
    try:
        decoded = base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4))
        claims = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, binascii.Error, RecursionError) as exc:
        raise CLIError('The access token has an invalid JWT payload.') from exc
    if not isinstance(claims, dict):
        raise CLIError('The access token has an invalid JWT payload.')
    return claims


def parse_access_token(token, subscription_id, resource, now=None):
    """JWT fields are hints; ARM alone validates the signature and access rights."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
        raise CLIError('--access-token must contain a JWT access token.')
    subscription_id = guid(subscription_id, 'Subscription ID')
    claims = _claims(token)
    tenant_id = guid(claims.get('tid'), 'Token tenant (tid)')
    expires_on = claims.get('exp')
    if type(expires_on) is not int or expires_on <= 0:
        raise CLIError('The token must have a numeric expiration (exp).')
    now = int(time.time()) if now is None else int(now)
    if expires_on - now <= MIN_LIFETIME:
        raise CLIError('The access token expires in five minutes or less; obtain a new token.')
    not_before = claims.get('nbf')
    if isinstance(not_before, int) and not_before > now + 60:
        raise CLIError('The access token is not valid yet.')
    audience = claims.get('aud')
    if not isinstance(audience, str) or not isinstance(resource, str):
        raise CLIError('The token audience does not match the active cloud ARM resource.')
    parsed = urlparse(audience)
    if (parsed.scheme != 'https' or parsed.username or parsed.password
            or audience.rstrip('/').lower() != resource.rstrip('/').lower()):
        raise CLIError('The token audience does not match the active cloud ARM resource.')
    object_id = claims.get('oid')
    if object_id is not None:
        object_id = guid(object_id, 'Token object ID (oid)')
    return AccessToken(token, subscription_id, tenant_id, expires_on, object_id)
