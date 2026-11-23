"""Azure CLI handlers for access-token imports."""

from .importer import import_access_token, remove_files


def import_token(cmd, access_token, subscription_id, force=False):
    import_access_token(cmd.cli_ctx, access_token=access_token,
                        subscription_id=subscription_id, force=force)
    return {'importedSubscriptions': 1,
            'note': 'Access tokens cannot be refreshed; use a new token before it expires.'}


def remove_imports(cmd, subscription_id=None):
    count = remove_files(cmd.cli_ctx, subscription_id=subscription_id)
    return {'removedSubscriptions': count}
