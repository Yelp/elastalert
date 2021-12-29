import boto3
import os
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

import requests
from requests import RequestException
from requests.auth import AuthBase, HTTPBasicAuth

from elastalert.auth import RefeshableAWSRequestsAuth
from elastalert.util import EAException

def append_security_tenant(url, security_tenant):
    '''Appends the security_tenant query string parameter to the url'''
    parsed = urlsplit(url)

    if parsed.query:
        qs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    else:
        qs = []
    qs.append(('security_tenant', security_tenant))

    new_query = urlencode(qs)
    new_args = parsed._replace(query=new_query)
    new_url = urlunsplit(new_args)
    return new_url

class KibanaExternalUrlFormatter:
    '''Interface for formatting external Kibana urls'''

    def format(self, relative_url: str) -> str:
        raise NotImplementedError()

class AbsoluteKibanaExternalUrlFormatter(KibanaExternalUrlFormatter):
    '''Formats absolute external Kibana urls'''

    def __init__(self, base_url: str, security_tenant: str) -> None:
        self.base_url = base_url
        self.security_tenant = security_tenant

    def format(self, relative_url: str) -> str:
        url = urljoin(self.base_url, relative_url)
        if self.security_tenant:
            url = append_security_tenant(url, self.security_tenant)
        return url

class ShortKibanaExternalUrlFormatter(KibanaExternalUrlFormatter):
    '''Formats external urls using the Kibana Shorten URL API'''

    def __init__(self, base_url: str, auth: AuthBase, security_tenant: str) -> None:
        self.auth = auth
        self.security_tenant = security_tenant
        self.goto_url = urljoin(base_url, 'goto/')

        shorten_url = urljoin(base_url, 'api/shorten_url')
        if security_tenant:
            shorten_url = append_security_tenant(shorten_url, security_tenant)
        self.shorten_url = shorten_url

    def format(self, relative_url: str) -> str:
        # join with '/' to ensure relative to root of app
        long_url = urljoin('/', relative_url)
        if self.security_tenant:
            long_url = append_security_tenant(long_url, self.security_tenant)

        try:
            response = requests.post(
                url=self.shorten_url,
                auth=self.auth,
                headers={
                    'kbn-xsrf': 'elastalert',
                    'osd-xsrf': 'elastalert'
                },
                json={
                    'url': long_url
                }
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Failed to invoke Kibana Shorten URL API: %s" % e)

        response_body = response.json()
        url_id = response_body.get('urlId')

        goto_url = urljoin(self.goto_url, url_id)
        if self.security_tenant:
            goto_url = append_security_tenant(goto_url, self.security_tenant)
        return goto_url


def create_kibana_auth(kibana_url, rule) -> AuthBase:
    '''Creates a Kibana http authentication for use by requests'''

    # Basic
    username = rule.get('kibana_username')
    password = rule.get('kibana_password')
    if username and password:
        return HTTPBasicAuth(username, password)

    # AWS SigV4
    aws_region = rule.get('aws_region')
    if not aws_region:
        aws_region = os.environ.get('AWS_DEFAULT_REGION')
    if aws_region:

        aws_profile = rule.get('profile')
        session = boto3.session.Session(
            profile_name=aws_profile,
            region_name=aws_region
        )
        credentials = session.get_credentials()

        kibana_host = urlparse(kibana_url).hostname

        return RefeshableAWSRequestsAuth(
            refreshable_credential=credentials,
            aws_host=kibana_host,
            aws_region=aws_region,
            aws_service='es'
        )

    # Unauthenticated
    return None


def create_kibana_external_url_formatter(
    rule,
    shorten: bool,
    security_tenant: str
) -> KibanaExternalUrlFormatter:
    '''Creates a Kibana external url formatter'''

    base_url = rule.get('kibana_url')

    if shorten:
        auth = create_kibana_auth(base_url, rule)
        return ShortKibanaExternalUrlFormatter(base_url, auth, security_tenant)

    return AbsoluteKibanaExternalUrlFormatter(base_url, security_tenant)
