import json
import logging

from unittest import mock
import pytest
from requests import RequestException

from elastalert.util import EAException
from elastalert.loaders import FileRulesLoader
from elastalert.alerters.thehive import HiveAlerter

#### Test when description is not submitted under hive_alert_config
def test_load_description_1():
    rule = {'alert': [],
            'alert_text': '',
            'alert_text_type': 'alert_text_only',
            'description': 'test',
            'hive_alert_config': {'customFields': [{'name': 'test',
                                                    'type': 'string',
                                                    'value': 2}],
                                  'follow': True,
                                  'severity': 2,
                                  'source': 'elastalert',
                                  'status': 'New',
                                  'tags': ['test.port'],
                                  'tlp': 3,
                                  'type': 'external'},
            'hive_connection': {'hive_apikey': '',
                                'hive_host': 'https://localhost',
                                'hive_port': 9000},
            'hive_observable_data_mapping': [{'ip': 'test.ip', 'autonomous-system': 'test.as_number'}],
            'name': 'test-thehive',
            'tags': ['a', 'b'],
            'type': 'any'}
    
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HiveAlerter(rule)
    match = {
        "test": {
          "ip": "127.0.0.1",
          "port": 9876,
          "as_number": 1234
        },
        "@timestamp": "2021-05-09T14:43:30",
    }

    actual = alert.load_description(alert.create_alert_body(match), match)
    expected=alert.create_alert_body(match)
    assert actual == expected

#### Test when description is submitted under hive_alert_config but description_args is not
def test_load_description_2():
    rule = {'alert': [],
            'alert_text': '',
            'alert_text_type': 'alert_text_only',
            'description': 'test',
            'hive_alert_config': {'customFields': [{'name': 'test',
                                                    'type': 'string',
                                                    'value': 2}],
                                  'follow': True,
                                  'severity': 2,
                                  'source': 'elastalert',
                                  'description': 'TheHive description test',
                                  'status': 'New',
                                  'tags': ['test.port'],
                                  'tlp': 3,
                                  'type': 'external'},
            'hive_connection': {'hive_apikey': '',
                                'hive_host': 'https://localhost',
                                'hive_port': 9000},
            'hive_observable_data_mapping': [{'ip': 'test.ip', 'autonomous-system': 'test.as_number'}],
            'name': 'test-thehive',
            'tags': ['a', 'b'],
            'type': 'any'}
    
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HiveAlerter(rule)
    match = {
        "test": {
          "ip": "127.0.0.1",
          "port": 9876,
          "as_number": 1234
        },
        "@timestamp": "2021-05-09T14:43:30",
    }
    actual = alert.load_description(rule['hive_alert_config']['description'], match)
    expected = rule['hive_alert_config']['description']
    assert actual == expected


### Test with description_missing_value

def test_load_description_3():
    rule = {'alert': [],
            'alert_text': '',
            'alert_text_type': 'alert_text_only',
            'title': 'Unit test',
            'description': 'test',
            'hive_alert_config': {'customFields': [{'name': 'test',
                                                    'type': 'string',
                                                    'value': 2}],
                                  'follow': True,
                                  'severity': 2,
                                  'source': 'elastalert',
                                  'description_missing_value': '<Value not found in logs>',
                                  'description_args': [ 'title', 'test.ip', 'host' ],
                                  'description': '{0} from host:{2} to {1}',
                                  'status': 'New',
                                  'tags': ['test.port'],
                                  'tlp': 3,
                                  'type': 'external'},
            'hive_connection': {'hive_apikey': '',
                                'hive_host': 'https://localhost',
                                'hive_port': 9000},
            'hive_observable_data_mapping': [{'ip': 'test.ip', 'autonomous-system': 'test.as_number'}],
            'name': 'test-thehive',
            'tags': ['a', 'b'],
            'type': 'any'}
    
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HiveAlerter(rule)
    match = {
        "test": {
          "ip": "127.0.0.1",
          "port": 9876,
          "as_number": 1234
        },
        "@timestamp": "2021-05-09T14:43:30",
    }
    actual = alert.load_description(rule['hive_alert_config']['description'], match)
    expected = "Unit test from host:<Value not found in logs> to 127.0.0.1"
    assert actual == expected


### Test without description_missing_value, missing values a replaced by a default value <MISSING VALUE>
def test_load_description_4():
    rule = {'alert': [],
            'alert_text': '',
            'alert_text_type': 'alert_text_only',
            'title': 'Unit test',
            'description': 'test',
            'hive_alert_config': {'customFields': [{'name': 'test',
                                                    'type': 'string',
                                                    'value': 2}],
                                  'follow': True,
                                  'severity': 2,
                                  'source': 'elastalert',
                                  'description_args': [ 'title', 'test.ip', 'host' ],
                                  'description': '{0} from host:{2} to {1}',
                                  'status': 'New',
                                  'tags': ['test.port'],
                                  'tlp': 3,
                                  'type': 'external'},
            'hive_connection': {'hive_apikey': '',
                                'hive_host': 'https://localhost',
                                'hive_port': 9000},
            'hive_observable_data_mapping': [{'ip': 'test.ip', 'autonomous-system': 'test.as_number'}],
            'name': 'test-thehive',
            'tags': ['a', 'b'],
            'type': 'any'}
    
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HiveAlerter(rule)
    match = {
        "test": {
          "ip": "127.0.0.1",
          "port": 9876,
          "as_number": 1234
        },
        "@timestamp": "2021-05-09T14:43:30",
    }
    actual = alert.load_description(rule['hive_alert_config']['description'], match)
    expected = "Unit test from host:<MISSING VALUE> to 127.0.0.1"
    assert actual == expected

test_load_description_1()
test_load_description_2()
test_load_description_3()
test_load_description_4()
