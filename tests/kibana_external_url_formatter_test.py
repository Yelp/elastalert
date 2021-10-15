from typing import Any
import os
import pytest

import requests
from requests.auth import AuthBase, HTTPBasicAuth

from elastalert.kibana_external_url_formatter import AbsoluteKibanaExternalUrlFormatter
from elastalert.kibana_external_url_formatter import KibanaExternalUrlFormatter
from elastalert.kibana_external_url_formatter import ShortKibanaExternalUrlFormatter
from elastalert.kibana_external_url_formatter import append_security_tenant
from elastalert.kibana_external_url_formatter import create_kibana_auth
from elastalert.kibana_external_url_formatter import create_kibana_external_url_formatter

from elastalert.auth import RefeshableAWSRequestsAuth
from elastalert.util import EAException

from unittest import mock


class AbsoluteFormatTestCase:
    def __init__(
         self,
         base_url: str,
         relative_url: str,
         expected_url: str,
         security_tenant: str = None,
    ) -> None:
        self.base_url = base_url
        self.relative_url = relative_url
        self.expected_url = expected_url
        self.security_tenant = security_tenant


@pytest.mark.parametrize("test_case", [

    # Relative to Kibana plugin
    AbsoluteFormatTestCase(
        base_url='http://elasticsearch.test.org:9200/_plugin/kibana/',
        relative_url='app/dev_tools#/console',
        expected_url='http://elasticsearch.test.org:9200/_plugin/kibana/app/dev_tools#/console'
    ),

    # Relative to OpenSearch Dashboards
    AbsoluteFormatTestCase(
        base_url='http://opensearch.test.org/_dashboards/',
        relative_url='app/dev_tools#/console',
        expected_url='http://opensearch.test.org/_dashboards/app/dev_tools#/console'
    ),

    # Relative to root of dedicated Kibana domain
    AbsoluteFormatTestCase(
        base_url='http://kibana.test.org/',
        relative_url='/app/dev_tools#/console',
        expected_url='http://kibana.test.org/app/dev_tools#/console'
    ),

    # With security tenant
    AbsoluteFormatTestCase(
        base_url='http://kibana.test.org/',
        security_tenant='global',
        relative_url='/app/dev_tools#/console',
        expected_url='http://kibana.test.org/app/dev_tools?security_tenant=global#/console'
    ),
])
def test_absolute_kinbana_external_url_formatter(
    test_case: AbsoluteFormatTestCase
):
    formatter = AbsoluteKibanaExternalUrlFormatter(
        base_url=test_case.base_url,
        security_tenant=test_case.security_tenant
    )
    actualUrl = formatter.format(test_case.relative_url)
    assert actualUrl == test_case.expected_url


def mock_kibana_shorten_url_api(*args, **kwargs):
    class MockResponse:
        def __init__(self, status_code):
            self.status_code = status_code

        def json(self):
            return {
                'urlId': '62af3ebe6652370f85de91ccb3a3825f'
            }

        def raise_for_status(self):
            if self.status_code == 400:
                raise requests.exceptions.HTTPError()

    json = kwargs['json']
    url = json['url']

    if url.startswith('/app/'):
        return MockResponse(200)
    else:
        return MockResponse(400)


class ShortenUrlTestCase:
    def __init__(
         self,
         base_url: str,
         relative_url: str,
         expected_api_request: Any,
         expected_url: str,
         auth: AuthBase = None,
         security_tenant: str = None
    ) -> None:
        self.base_url = base_url
        self.relative_url = relative_url
        self.expected_api_request = expected_api_request
        self.expected_url = expected_url
        self.authorization = auth
        self.security_tenant = security_tenant


@mock.patch('requests.post', side_effect=mock_kibana_shorten_url_api)
@pytest.mark.parametrize("test_case", [

    # Relative to kibana plugin
    ShortenUrlTestCase(
        base_url='http://elasticsearch.test.org/_plugin/kibana/',
        relative_url='app/dev_tools#/console',
        expected_api_request={
            'url': 'http://elasticsearch.test.org/_plugin/kibana/api/shorten_url',
            'auth': None,
            'headers': {
                'kbn-xsrf': 'elastalert',
                'osd-xsrf': 'elastalert'
            },
            'json': {
                'url': '/app/dev_tools#/console'
            }
        },
        expected_url='http://elasticsearch.test.org/_plugin/kibana/goto/62af3ebe6652370f85de91ccb3a3825f'
    ),

    # Relative to root of dedicated Kibana domain
    ShortenUrlTestCase(
        base_url='http://kibana.test.org/',
        relative_url='/app/dev_tools#/console',
        expected_api_request={
            'url': 'http://kibana.test.org/api/shorten_url',
            'auth': None,
            'headers': {
                'kbn-xsrf': 'elastalert',
                'osd-xsrf': 'elastalert'
            },
            'json': {
                'url': '/app/dev_tools#/console'
            }
        },
        expected_url='http://kibana.test.org/goto/62af3ebe6652370f85de91ccb3a3825f'
    ),

    # With authentication
    ShortenUrlTestCase(
        base_url='http://kibana.test.org/',
        auth=HTTPBasicAuth('john', 'doe'),
        relative_url='/app/dev_tools#/console',
        expected_api_request={
            'url': 'http://kibana.test.org/api/shorten_url',
            'auth': HTTPBasicAuth('john', 'doe'),
            'headers': {
                'kbn-xsrf': 'elastalert',
                'osd-xsrf': 'elastalert'
            },
            'json': {
                'url': '/app/dev_tools#/console'
            }
        },
        expected_url='http://kibana.test.org/goto/62af3ebe6652370f85de91ccb3a3825f'
    ),

    # With security tenant
    ShortenUrlTestCase(
        base_url='http://kibana.test.org/',
        security_tenant='global',
        relative_url='/app/dev_tools#/console',
        expected_api_request={
            'url': 'http://kibana.test.org/api/shorten_url?security_tenant=global',
            'auth': None,
            'headers': {
                'kbn-xsrf': 'elastalert',
                'osd-xsrf': 'elastalert'
            },
            'json': {
                'url': '/app/dev_tools?security_tenant=global#/console'
            }
        },
        expected_url='http://kibana.test.org/goto/62af3ebe6652370f85de91ccb3a3825f?security_tenant=global'
    )
])
def test_short_kinbana_external_url_formatter(
    mock_post: mock.MagicMock,
    test_case: ShortenUrlTestCase
):
    formatter = ShortKibanaExternalUrlFormatter(
        base_url=test_case.base_url,
        auth=test_case.authorization,
        security_tenant=test_case.security_tenant,
    )

    actualUrl = formatter.format(test_case.relative_url)
    assert actualUrl == test_case.expected_url

    mock_post.assert_called_once_with(**test_case.expected_api_request)


@mock.patch('requests.post', side_effect=mock_kibana_shorten_url_api)
def test_short_kinbana_external_url_formatter_request_exception(mock_post: mock.MagicMock):
    formatter = ShortKibanaExternalUrlFormatter(
        base_url='http://kibana.test.org',
        auth=None,
        security_tenant=None,
    )
    with pytest.raises(EAException, match="Failed to invoke Kibana Shorten URL API"):
        formatter.format('http://wacky.org')
    mock_post.assert_called_once()


def test_create_kibana_external_url_formatter_without_shortening():
    formatter = create_kibana_external_url_formatter(
        rule={
            'kibana_url': 'http://kibana.test.org/'
        },
        shorten=False,
        security_tenant='foo'
    )
    assert type(formatter) is AbsoluteKibanaExternalUrlFormatter
    assert formatter.base_url == 'http://kibana.test.org/'
    assert formatter.security_tenant == 'foo'


def test_create_kibana_external_url_formatter_with_shortening():
    formatter = create_kibana_external_url_formatter(
        rule={
            'kibana_url': 'http://kibana.test.org/',
            'kibana_username': 'john',
            'kibana_password': 'doe'
        },
        shorten=True,
        security_tenant='foo'
    )
    assert type(formatter) is ShortKibanaExternalUrlFormatter
    assert formatter.auth == HTTPBasicAuth('john', 'doe')
    assert formatter.security_tenant == 'foo'
    assert formatter.goto_url == 'http://kibana.test.org/goto/'
    assert formatter.shorten_url == 'http://kibana.test.org/api/shorten_url?security_tenant=foo'


@pytest.mark.parametrize("test_case", [
    # Trivial
    {
        'url': 'http://test.org',
        'expected':  'http://test.org?security_tenant=foo'
    },
    # With query
    {
        'url': 'http://test.org?year=2021',
        'expected':  'http://test.org?year=2021&security_tenant=foo'
    },
    # With fragment
    {
        'url': 'http://test.org#fragement',
        'expected':  'http://test.org?security_tenant=foo#fragement'
    },
    # With query & fragment
    {
        'url': 'http://test.org?year=2021#fragement',
        'expected':  'http://test.org?year=2021&security_tenant=foo#fragement'
    },
])
def test_append_security_tenant(test_case):
    url = test_case.get('url')
    expected = test_case.get('expected')
    result = append_security_tenant(url=url, security_tenant='foo')
    assert result == expected


def test_create_kibana_auth_basic():
    auth = create_kibana_auth(
        kibana_url='http://kibana.test.org',
        rule={
            'kibana_username': 'john',
            'kibana_password': 'doe',
        }
    )
    assert auth == HTTPBasicAuth('john', 'doe')


@mock.patch.dict(
    os.environ,
    {
        'AWS_DEFAULT_REGION': '',
        'AWS_ACCESS_KEY_ID': 'access',
        'AWS_SECRET_ACCESS_KEY': 'secret',
    },
    clear=True
)
def test_create_kibana_auth_aws_explicit_region():
    auth = create_kibana_auth(
        kibana_url='http://kibana.test.org',
        rule={
            'aws_region': 'us-east-1'
        }
    )
    assert type(auth) is RefeshableAWSRequestsAuth
    assert auth.aws_host == 'kibana.test.org'
    assert auth.aws_region == 'us-east-1'
    assert auth.service == 'es'
    assert auth.aws_access_key == 'access'
    assert auth.aws_secret_access_key == 'secret'
    assert auth.aws_token is None


@mock.patch.dict(
    os.environ,
    {
        'AWS_DEFAULT_REGION': 'us-east-2',
        'AWS_ACCESS_KEY_ID': 'access',
        'AWS_SECRET_ACCESS_KEY': 'secret',
    },
    clear=True
)
def test_create_kibana_auth_aws_implicit_region():
    auth = create_kibana_auth(
        kibana_url='http://kibana.test.org',
        rule={}
    )
    assert type(auth) is RefeshableAWSRequestsAuth
    assert auth.aws_host == 'kibana.test.org'
    assert auth.aws_region == 'us-east-2'
    assert auth.service == 'es'
    assert auth.aws_access_key == 'access'
    assert auth.aws_secret_access_key == 'secret'
    assert auth.aws_token is None


@mock.patch.dict(
    os.environ,
    {},
    clear=True
)
def test_create_kibana_auth_unauthenticated():
    auth = create_kibana_auth(
        kibana_url='http://kibana.test.org',
        rule={}
    )
    assert auth is None


def test_kibana_external_url_formatter_not_implemented():
    formatter = KibanaExternalUrlFormatter()
    with pytest.raises(NotImplementedError):
        formatter.format('test')
