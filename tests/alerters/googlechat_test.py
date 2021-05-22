import json

import mock
import pytest
from requests import RequestException

from elastalert.alerters.googlechat import GoogleChatAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_google_chat_basic():
    rule = {
        'name': 'Test GoogleChat Rule',
        'type': 'any',
        'googlechat_webhook_url': 'http://xxxxxxx',
        'googlechat_format': 'basic',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GoogleChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'text': 'Test GoogleChat Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        rule['googlechat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_google_chat_card():
    rule = {
        'name': 'Test GoogleChat Rule',
        'type': 'any',
        'googlechat_webhook_url': 'http://xxxxxxx',
        'googlechat_format': 'card',
        'googlechat_header_title': 'xxxx1',
        'googlechat_header_subtitle': 'xxxx2',
        'googlechat_header_image': 'http://xxxx/image.png',
        'googlechat_footer_kibanalink': 'http://xxxxx/kibana',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GoogleChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'cards': [{
            'header': {
                'title': rule['googlechat_header_title'],
                'subtitle': rule['googlechat_header_subtitle'],
                'imageUrl': rule['googlechat_header_image']
            },
            'sections': [
                {
                    'widgets': [{
                        "textParagraph": {
                            'text': 'Test GoogleChat Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
                        }
                    }]
                },
                {
                    'widgets': [{
                        'buttons': [{
                            'textButton': {
                                'text': 'VISIT KIBANA',
                                'onClick': {
                                    'openLink': {
                                        'url': rule['googlechat_footer_kibanalink']
                                    }
                                }
                            }
                        }]
                    }]
                }
            ]}
        ]
    }

    mock_post_request.assert_called_once_with(
        rule['googlechat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_google_chat_ea_exception():
    try:
        rule = {
            'name': 'Test GoogleChat Rule',
            'type': 'any',
            'googlechat_webhook_url': 'http://xxxxxxx',
            'googlechat_format': 'card',
            'googlechat_header_title': 'xxxx1',
            'googlechat_header_subtitle': 'xxxx2',
            'googlechat_header_image': 'http://xxxx/image.png',
            'googlechat_footer_kibanalink': 'http://xxxxx/kibana',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = GoogleChatAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True
