"""Arguments for direct access-token import and removal."""


def load_arguments(self, _):
    with self.argument_context('token-login import') as context:
        context.argument('access_token', options_list=['--access-token'],
                         required=True,
                         help='ARM bearer token. WARNING: visible in shell history and process listings.')
        context.argument('subscription_id', options_list=['--subscription-id'], required=True,
                         help='Subscription ID to associate with this access token.')

    with self.argument_context('token-login remove') as context:
        context.argument('subscription_id', options_list=['--subscription-id'],
                         help='Remove only the specified imported subscription (default: all imports).')
