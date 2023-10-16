import boto3
from botocore.exceptions import ClientError
import logging
from datetime import datetime, timezone
import json

from auth import FHIRAuth

logger = logging.getLogger(__name__)

def snake_to_camel_case(s: str):
    """
    ehr params are passed to fhir server constructor using
    snake_case keys, but the payload on the wire is in camelCase.
    This function converts one to the other.
    """
    first, *rest = s.split('_')
    # Special case - if no underscores, just return the original string
    # lets us use orgID as a parameter without turning it into orgid
    if not rest:
        return s

    # Otherwise remap to camel case
    return ''.join([first.lower(), *map(str.title, rest)])


def remapKeyCase(d: dict):
    """
    Given a dictionary d, replace snake_case keys
    with the equivalent camelCase ones.
    """
    return { snake_to_camel_case(k): v for k, v in d.items() }


class TokenServerAuth(FHIRAuth):
    """
    Rincon token server auth for FHIR servers.
    """
    auth_type = 'tokenserver'

    def __init__(self, state=None):
        self._token_server_arn = None
        self._token_server_params = None
        self.access_token = None
        self.expires_at = None
        self.base_uri = None
        super(TokenServerAuth, self).__init__(state=state)

    @property
    def ready(self):
        if self.expires_at and self.expires_at < datetime.now(timezone.utc):
            self.reset()
        return bool(self.access_token)

    def reset(self):
        super(TokenServerAuth, self).reset()
        self.access_token = None
        self.expires_at = None

    def authorize(self, server):
        """
        Make call to token server to get a new token.
        """
        client = boto3.client('lambda')
        logger.debug(f'Token server params = {self._token_server_params}')
        params = remapKeyCase(self._token_server_params)
        try:
            logger.debug(f'FHIR client requesting token for {params["ehrName"]}')
            response = client.invoke(
                FunctionName=self._token_server_arn,
                Payload=json.dumps(params)
            )

            if 'Error' in response:
                logger.error(
                    f'FHIR client: token server request failed: '
                    f'{response["Error"]["Code"]}: '
                    f'{response["Error"]["Message"]}')
                raise Exception(f'Unable to get token from token server')

            results = json.loads(response["Payload"].read())
            logger.debug(f"Auth server result={results}")
            if results['statusCode'] != 200:
                msg = (
                    f'Request to token server failed: {results["statusCode"]}: '
                    f'{results["errorDescription"]}')
                logger.error(msg)
                raise Exception(msg)

            self.access_token = results["token"]
            self.expires_at = datetime.fromisoformat(results["expiresAt"])
            self.base_uri = results["apiBase"]

        except ClientError as err:
            logger.error(
                f'Lambda request to token server failed, code '
                f'{err.response["Error"]["Code"]}'
            )
            raise

        return {}

    def reauthorize(self, server):
        self.authorize(server)

    def _is_expired(self):
        # If we have an expiration date and it's expired, return true
        # Otherwise return false
        return bool(self.expires_at) and self.expires_at < datetime.now(timezone.utc)

    def can_sign_headers(self):
        # Do we have a token and is it not expired?
        return bool(self.access_token) and not self._is_expired()

    def signed_headers(self, headers):
        if not self.can_sign_headers():
            raise Exception('Cannot sign heards, don\'t have an access token')

        if headers is None:
            headers = {}

        headers['Authorization'] = f'Bearer {self.access_token}'
        return headers

    @property
    def state(self):
        s = super(TokenServerAuth, self).state
        if self._token_server_arn is not None:
            s['token_server_function_name'] = self._token_server_arn
        if self._token_server_params is not None:
            s['token_server_params'] = self._token_server_params
        if self.access_token is not None:
            s['access_token'] = self.access_token
        if self.base_uri is not None:
            s['base_uri'] = self.base_uri

    def from_state(self, state):
        """
        Update instance variables from given state information
        """
        super(TokenServerAuth, self).from_state(state)

        self._token_server_arn = state.get('token_server_function_name', self._token_server_arn)
        self._token_server_params = state.get('token_server_params', self._token_server_params)
        self.access_token = state.get('access_token', self.access_token)
        self.base_uri = state.get('base_uri', self.base_uri)

logger.debug('Registering token server auth type')
TokenServerAuth.register()
