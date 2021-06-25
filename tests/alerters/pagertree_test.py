import json
import re
import uuid
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.pagertree import PagerTreeAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_pagertree(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test PagerTree Rule',
        'type': 'any',
        'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerTreeAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'event_type': 'create',
        'Id': str(uuid.uuid4()),
        'Title': 'Test PagerTree Rule',
        'Description': 'Test PagerTree Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        rule['pagertree_integration_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    uuid4hex = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    match = uuid4hex.match(actual_data['Id'])
    assert bool(match) is True
    assert expected_data["event_type"] == actual_data['event_type']
    assert expected_data["Title"] == actual_data['Title']
    assert expected_data["Description"] == actual_data['Description']
    assert ('elastalert', logging.INFO, 'Trigger sent to PagerTree') == caplog.record_tuples[0]


def test_pagertree_proxy():
    rule = {
        'name': 'Test PagerTree Rule',
        'type': 'any',
        'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
        'pagertree_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerTreeAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'event_type': 'create',
        'Id': str(uuid.uuid4()),
        'Title': 'Test PagerTree Rule',
        'Description': 'Test PagerTree Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        rule['pagertree_integration_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    uuid4hex = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    match = uuid4hex.match(actual_data['Id'])
    assert bool(match) is True
    assert expected_data["event_type"] == actual_data['event_type']
    assert expected_data["Title"] == actual_data['Title']
    assert expected_data["Description"] == actual_data['Description']


def test_pagertree_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test PagerTree Rule',
            'type': 'any',
            'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
            'pagertree_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = PagerTreeAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to PagerTree: ' in str(ea)


def test_pagertree_getinfo():
    rule = {
        'name': 'Test PagerTree Rule',
        'type': 'any',
        'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerTreeAlerter(rule)

    expected_data = {
        'type': 'pagertree',
        'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('pagertree_integration_url, expected_data', [
    ('',  'Missing required option(s): pagertree_integration_url'),
    ('https://api.pagertree.com/integration/xxxxx',
        {
            'type': 'pagertree',
            'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx'
        }),
])
def test_pagertree_required_error(pagertree_integration_url, expected_data):
    try:
        rule = {
            'name': 'Test PagerTree Rule',
            'type': 'any',
            'alert': []
        }

        if pagertree_integration_url:
            rule['pagertree_integration_url'] = pagertree_integration_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = PagerTreeAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
