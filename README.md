# Azure CLI token-login extension

Authenticate built-in Azure CLI commands with a **short-lived ARM access token**
without interactive sign-in. This extension targets Azure CLI 2.81.0, MSAL
1.39.0, MSAL Extensions 1.3.1, and Linux. It imports a token into the CLI's
subscription profile (`azureProfile.json`) and MSAL cache
(`msal_token_cache.json`). This is **unsupported, version-pinned integration**:
Azure CLI has no public bearer-token login API. Azure validates the token on
requests; decoding its JWT locally does not verify its signature or permissions.
The extension cannot refresh tokens and MSAL stops using them with fewer than
five minutes remaining.

## Install

From the `scripts/` directory:

```sh
python -m pip wheel --no-deps --no-build-isolation ./azure_token_login -w ./dist
az extension add --source ./dist/azure_token_login-0.1.0-py3-none-any.whl --yes
```

**Before importing:** the Azure config directory must be owned by you and mode
`0700`; its MSAL token cache must be owner-only (`0600`). The extension does not
change permissions automatically. On this machine `~/.azure` is currently
`0777`; secure it with `chmod 700 "$HOME/.azure"` or set `AZURE_CONFIG_DIR`
to a private directory **before installing** the extension there. Back up your
config separately if restoring existing login state is especially important.

## Import and remove

The import command requires `--access-token` and `--subscription-id`. Supply the
JWT itself, not a filename or JSON wrapper:

```sh
az token-login import --access-token "$ACCESS_TOKEN" --subscription-id "$SUBSCRIPTION_ID"
az account set --subscription "$SUBSCRIPTION_ID"
az group list --subscription "$SUBSCRIPTION_ID"
```

To replace an unexpired imported token, pass `-f` (or `--force`):

```sh
az token-login import --access-token "$NEW_ACCESS_TOKEN" --subscription-id "$SUBSCRIPTION_ID" -f
```

An imported token whose `exp` is in the past is replaced automatically without
`-f`. The **new** token must still have more than five minutes remaining because
MSAL cannot use it near expiry. `-f` does not bypass token validation or checks
that the old cached credential and profile are still owned by this extension.
For older imports whose expiry cannot be confirmed from the cache, use `-f`.

**Security warning:** the expanded token appears in the `az` process arguments.
It can be visible to other local processes and may be recorded in shell history,
Azure CLI debug output, or monitoring tools. Using an environment variable in
the example avoids placing its *literal text* in the command line you type but
does **not** remove it from the process arguments. Do not enable debug logging
or share command transcripts containing the token. The extension itself never
prints it. The supplied subscription ID is a local association; Azure still
checks whether that token is authorized for the subscription.

Importing an existing subscription changes **only that subscription's account
association** in the CLI profile. Other credentials are not overwritten. If
there is no active default, this import becomes the default. To restore a
previous association and remove the imported cache entry:

```sh
az token-login remove --subscription-id "$SUBSCRIPTION_ID"
az token-login remove  # all imported subscriptions
```

Removing an import restores its original account association if that association
still belongs to the imported account. When restoring an earlier association,
changes to descriptive subscription metadata (such as its name or state) are
preserved. If another login has replaced the association, removal leaves that
profile entry alone and cleans up only the original imported credential. A changed
cached token or shared account still prevents removal to avoid deleting another
login's credentials.

## List imported subscriptions

```sh
az token-login list --output table
az token-login list --output json
```

Example (fabricated values):

```json
[
  {
    "subscriptionId": "33333333-3333-4333-8333-333333333333",
    "name": "Example subscription",
    "tenantId": "11111111-1111-4111-8111-111111111111",
    "cloud": "AzureCloud",
    "isDefault": true,
    "expiresOn": "2027-01-01T00:00:00Z",
    "tokenStatus": "valid",
    "accountStatus": "present",
    "profileStatus": "associated",
    "operationStatus": "complete"
  }
]
```

`list` reports only imports tracked by this extension, including imports from
other Azure clouds. It returns an empty array when none are recorded. Each row
contains the subscription ID, name, tenant ID, cloud, whether it is currently
the default (`null` if the profile association changed or disappeared), and
the effective expiry time in UTC (`expiresOn`, or `null` if unknown). The
effective expiry is the earlier of the imported token's recorded expiry and its
current MSAL cache expiry. `tokenStatus` is `valid`, `expiring`
(five minutes or less remain), `expired`, `missing`, `changed` (the cached token
no longer matches this import), or `unknown` (expiry unavailable).
`accountStatus` reports whether the matching MSAL account is `present`,
`missing`, or `changed`. `profileStatus` identifies whether the subscription is
still associated with the imported account; `operationStatus` identifies
interrupted imports or removals. Even with `valid` / `present` / `associated`
statuses, only Azure can verify the token's signature and permissions.

**The extension never prints bearer tokens or token hashes.** Its list handler
does not change profile/state/cache contents or create a config directory.
Azure CLI itself may create configuration and command-log files before the
extension runs; when no imports are recorded, listing still returns `[]`.
Because listing does not take the import lock, running it concurrently with
another `az` process can briefly show inconsistent statuses.

The importer uses MSAL's cache lock and checks for intervening profile changes,
but ordinary `az` profile writes do not honor its lock. **Do not run other `az`
processes concurrently with import, replacement, or removal.** The profile,
cache, and recovery journal cannot be updated as one atomic transaction. An
ordinary replacement failure attempts to restore the previous import. If the
process is interrupted, run `az token-login remove` to finish its recovery
journal; a previously removed access token cannot be recovered after an
interrupted replacement. An incoming token can then be imported again.

Only ARM-audience JWT access tokens containing tenant and expiry claims are
supported. **A Microsoft Graph token is rejected** because its audience does not
match the ARM scope requested by ordinary management commands such as
`az group list`. Azure CLI's Graph commands request a separate Graph scope;
a Graph token could serve those commands only if imported under that scope, and
would still not authenticate ARM commands. An access token cannot be exchanged
for a different audience without another authentication flow. This extension
does not create tokens for Graph, data-plane services, claims challenges, or
other tenants. A cached account with a refresh token is not borrowed; a
synthetic account is used instead. Replace a recorded import with `-f`, or
without it once the old access token has expired.

Keep `token-login-state.json` private: it contains account metadata. Tests use
fabricated tokens only:

```sh
python -I -B -m unittest discover -s ./azure_token_login/tests -v
```
