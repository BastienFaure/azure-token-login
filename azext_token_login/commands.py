"""Commands provided by the token-login extension."""


def load_command_table(self, _):
    with self.command_group('token-login') as group:
        group.custom_command('import', 'import_token')
        group.custom_command('remove', 'remove_imports')
