# -*- coding: utf-8 -*-
import logging
import os
import pytest

from datetime import datetime
from datetime import timedelta

from dateutil.parser import parse as dt
from dateutil.tz import tzutc

from unittest import mock

from elastalert.util import add_raw_postfix
from elastalert.util import build_es_conn_config
from elastalert.util import dt_to_int
from elastalert.util import dt_to_ts
from elastalert.util import dt_to_ts_with_format
from elastalert.util import EAException
from elastalert.util import elasticsearch_client
from elastalert.util import flatten_dict
from elastalert.util import format_index
from elastalert.util import get_module
from elastalert.util import inc_ts
from elastalert.util import lookup_es_key
from elastalert.util import parse_deadline
from elastalert.util import parse_duration
from elastalert.util import pytzfy
from elastalert.util import replace_dots_in_field_names
from elastalert.util import resolve_string
from elastalert.util import set_es_key
from elastalert.util import should_scrolling_continue
from elastalert.util import total_seconds
from elastalert.util import ts_to_dt_with_format
from elastalert.util import ts_utc_to_tz
from elastalert.util import expand_string_into_dict
from elastalert.util import unixms_to_dt
from elastalert.util import format_string
from elastalert.util import pretty_ts


@pytest.mark.parametrize('spec, expected_delta', [
    ('hours=2', timedelta(hours=2)),
    ('minutes=30', timedelta(minutes=30)),
    ('seconds=45', timedelta(seconds=45)),
])
def test_parse_duration(spec, expected_delta):
    """``unit=num`` specs can be translated into ``timedelta`` instances."""
    assert parse_duration(spec) == expected_delta


@pytest.mark.parametrize('spec, expected_deadline', [
    ('hours=2', dt('2017-07-07T12:00:00.000Z')),
    ('minutes=30', dt('2017-07-07T10:30:00.000Z')),
    ('seconds=45', dt('2017-07-07T10:00:45.000Z')),
])
def test_parse_deadline(spec, expected_deadline):
    """``unit=num`` specs can be translated into ``datetime`` instances."""

    # Note: Can't mock ``utcnow`` directly because ``datetime`` is a built-in.
    class MockDatetime(datetime):
        @staticmethod
        def utcnow():
            return dt('2017-07-07T10:00:00.000Z')

    with mock.patch('datetime.datetime', MockDatetime):
        assert parse_deadline(spec) == expected_deadline


def test_setting_keys(ea):
    expected = 12467267
    record = {
        'Message': '12345',
        'Fields': {
            'ts': 'fail',
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    # Set the value
    assert set_es_key(record, 'Fields.ts', expected)

    # Get the value again
    assert lookup_es_key(record, 'Fields.ts') == expected


def test_looking_up_missing_keys(ea):
    record = {
        'Message': '12345',
        'Fields': {
            'severity': 'large',
            'user': 'jimmay',
            'null': None
        }
    }

    assert lookup_es_key(record, 'Fields.ts') is None

    assert lookup_es_key(record, 'Fields.null.foo') is None


def test_looking_up_nested_keys(ea):
    expected = 12467267
    record = {
        'Message': '12345',
        'Fields': {
            'ts': expected,
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    assert lookup_es_key(record, 'Fields.ts') == expected


def test_looking_up_nested_composite_keys(ea):
    expected = 12467267
    record = {
        'Message': '12345',
        'Fields': {
            'ts.value': expected,
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    assert lookup_es_key(record, 'Fields.ts.value') == expected


def test_looking_up_arrays(ea):
    record = {
        'flags': [1, 2, 3],
        'objects': [
            {'foo': 'bar'},
            {'foo': [{'bar': 'baz'}]},
            {'foo': {'bar': 'baz'}}
        ]
    }
    assert lookup_es_key(record, 'flags[0]') == 1
    assert lookup_es_key(record, 'flags[1]') == 2
    assert lookup_es_key(record, 'objects[0]foo') == 'bar'
    assert lookup_es_key(record, 'objects[1]foo[0]bar') == 'baz'
    assert lookup_es_key(record, 'objects[2]foo.bar') == 'baz'
    assert lookup_es_key(record, 'objects[1]foo[1]bar') is None
    assert lookup_es_key(record, 'objects[1]foo[0]baz') is None


def test_add_raw_postfix(ea):
    expected = 'foo.raw'
    assert add_raw_postfix('foo', False) == expected
    assert add_raw_postfix('foo.raw', False) == expected
    expected = 'foo.keyword'
    assert add_raw_postfix('foo', True) == expected
    assert add_raw_postfix('foo.keyword', True) == expected


def test_replace_dots_in_field_names(ea):
    actual = {
        'a': {
            'b.c': 'd',
            'e': {
                'f': {
                    'g.h': 0
                }
            }
        },
        'i.j.k': 1,
        'l': {
            'm': 2
        }
    }
    expected = {
        'a': {
            'b_c': 'd',
            'e': {
                'f': {
                    'g_h': 0
                }
            }
        },
        'i_j_k': 1,
        'l': {
            'm': 2
        }
    }
    assert replace_dots_in_field_names(actual) == expected
    assert replace_dots_in_field_names({'a': 0, 1: 2}) == {'a': 0, 1: 2}


def test_resolve_string(ea):
    match = {
        'name': 'mySystem',
        'temperature': 45,
        'humidity': 80.56,
        'sensors': ['outsideSensor', 'insideSensor'],
        'foo': {'bar': 'baz'}
    }

    expected_outputs = [
        "mySystem is online <MISSING VALUE>",
        "Sensors ['outsideSensor', 'insideSensor'] in the <MISSING VALUE> have temp 45 and 80.56 humidity",
        "Actuator <MISSING VALUE> in the <MISSING VALUE> has temp <MISSING VALUE>",
        'Something baz']
    old_style_strings = [
        "%(name)s is online %(noKey)s",
        "Sensors %(sensors)s in the %(noPlace)s have temp %(temperature)s and %(humidity)s humidity",
        "Actuator %(noKey)s in the %(noPlace)s has temp %(noKey)s",
        'Something %(foo.bar)s']

    assert resolve_string(old_style_strings[0], match) == expected_outputs[0]
    assert resolve_string(old_style_strings[1], match) == expected_outputs[1]
    assert resolve_string(old_style_strings[2], match) == expected_outputs[2]
    assert resolve_string(old_style_strings[3], match) == expected_outputs[3]

    new_style_strings = [
        "{name} is online {noKey}",
        "Sensors {sensors} in the {noPlace} have temp {temperature} and {humidity} humidity",
        "Actuator {noKey} in the {noPlace} has temp {noKey}",
        "Something {foo[bar]}"]

    assert resolve_string(new_style_strings[0], match) == expected_outputs[0]
    assert resolve_string(new_style_strings[1], match) == expected_outputs[1]
    assert resolve_string(new_style_strings[2], match) == expected_outputs[2]
    assert resolve_string(new_style_strings[3], match) == expected_outputs[3]


def test_format_index():
    pattern = 'logstash-%Y.%m.%d'
    pattern2 = 'logstash-%Y.%W'
    date = dt('2018-06-25T12:00:00Z')
    date2 = dt('2018-06-26T12:00:00Z')
    assert sorted(format_index(pattern, date, date).split(',')) == ['logstash-2018.06.25']
    assert sorted(format_index(pattern, date, date2).split(',')) == ['logstash-2018.06.25', 'logstash-2018.06.26']
    assert sorted(format_index(pattern, date, date2, True).split(',')) == ['logstash-2018.06.24',
                                                                           'logstash-2018.06.25',
                                                                           'logstash-2018.06.26']
    assert sorted(format_index(pattern2, date, date2, True).split(',')) == ['logstash-2018.25', 'logstash-2018.26']


def test_should_scrolling_continue():
    rule_no_max_scrolling = {'max_scrolling_count': 0, 'scrolling_cycle': 1}
    rule_reached_max_scrolling = {'max_scrolling_count': 2, 'scrolling_cycle': 2}
    rule_before_first_run = {'max_scrolling_count': 0, 'scrolling_cycle': 0}
    rule_before_max_scrolling = {'max_scrolling_count': 2, 'scrolling_cycle': 1}
    rule_over_max_scrolling = {'max_scrolling_count': 2, 'scrolling_cycle': 3}

    assert should_scrolling_continue(rule_no_max_scrolling) is True
    assert should_scrolling_continue(rule_reached_max_scrolling) is False
    assert should_scrolling_continue(rule_before_first_run) is True
    assert should_scrolling_continue(rule_before_max_scrolling) is True
    assert should_scrolling_continue(rule_over_max_scrolling) is False


def test_ts_to_dt_with_format1():
    assert ts_to_dt_with_format('2021/02/01 12:30:00', '%Y/%m/%d %H:%M:%S') == dt('2021-02-01 12:30:00+00:00')


def test_ts_to_dt_with_format2():
    assert ts_to_dt_with_format('01/02/2021 12:30:00', '%d/%m/%Y %H:%M:%S') == dt('2021-02-01 12:30:00+00:00')


def test_ts_to_dt_with_format3():
    date = datetime(2021, 7, 6, hour=0, minute=0, second=0)
    assert ts_to_dt_with_format(date, '') == dt('2021-7-6 00:00')


def test_ts_to_dt_with_format4():
    assert ts_to_dt_with_format('01/02/2021 12:30:00 +0900', '%d/%m/%Y %H:%M:%S %z') == dt('2021-02-01 12:30:00+09:00')


def test_dt_to_ts_with_format1():
    assert dt_to_ts_with_format(dt('2021-02-01 12:30:00+00:00'), '%Y/%m/%d %H:%M:%S') == '2021/02/01 12:30:00'


def test_dt_to_ts_with_format2():
    assert dt_to_ts_with_format(dt('2021-02-01 12:30:00+00:00'), '%d/%m/%Y %H:%M:%S') == '01/02/2021 12:30:00'


def test_dt_to_ts_with_format3():
    assert dt_to_ts_with_format('2021-02-01 12:30:00+00:00', '%d/%m/%Y %H:%M:%S') == '2021-02-01 12:30:00+00:00'


def test_flatten_dict():
    assert flatten_dict({'test': 'value1', 'test2': 'value2'}) == {'test': 'value1', 'test2': 'value2'}


def test_pytzfy1():
    assert pytzfy(dt('2021-02-01 12:30:00+00:00')) == dt('2021-02-01 12:30:00+00:00')


def test_pytzfy2():
    assert pytzfy(datetime(2018, 12, 31, 5, 0, 30, 1000)) == dt('2018-12-31 05:00:30.001000')


def test_get_module():
    with pytest.raises(EAException) as ea:
        get_module('test')
    assert 'Could not import module' in str(ea)


def test_dt_to_ts(caplog):
    caplog.set_level(logging.WARNING)
    dt_to_ts('a')
    user, level, message = caplog.record_tuples[0]
    assert 'elastalert' == user
    assert logging.WARNING == level
    assert 'Expected datetime, got' in message


def test_ts_utc_to_tz():
    date = datetime(2021, 7, 6, hour=0, minute=0, second=0)
    actual_data = ts_utc_to_tz(date, 'Europe/Istanbul')
    assert '2021-07-06 03:00:00+03:00' == str(actual_data)


test_build_es_conn_config_param = 'es_host, es_port, es_conn_timeout, es_send_get_body_as, ssl_show_warn, es_username, '
test_build_es_conn_config_param += 'es_password, es_api_key, es_bearer, aws_region, profile, use_ssl, verify_certs, '
test_build_es_conn_config_param += 'ca_certs, client_cert,client_key,es_url_prefix, expected_data'


@pytest.mark.parametrize(test_build_es_conn_config_param, [
    ('',          '',   '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', True),
    ('localhost', '',   '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', True),
    ('localhost', 9200, '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
        {
            'use_ssl': False,
            'verify_certs': True,
            'ca_certs': None,
            'client_cert': None,
            'client_key': None,
            'http_auth': None,
            'es_username': None,
            'es_password': None,
            'es_api_key': None,
            'es_bearer': None,
            'aws_region': None,
            'profile': None,
            'headers': None,
            'es_host': 'localhost',
            'es_port': 9200,
            'es_url_prefix': '',
            'es_conn_timeout': 20,
            'send_get_body_as': 'GET',
            'ssl_show_warn': True
        }),
    ('localhost', 9200, 30, 'POST', False, 'user', 'pass', 'key', 'bearer', 'us-east-1', 'default',
     True, False, '/path/to/cacert.pem', '/path/to/client_cert.pem', '/path/to/client_key.key', 'elasticsearch',
        {
            'use_ssl': True,
            'verify_certs': False,
            'ca_certs': '/path/to/cacert.pem',
            'client_cert': '/path/to/client_cert.pem',
            'client_key': '/path/to/client_key.key',
            'http_auth': None,
            'es_username': 'user',
            'es_password': 'pass',
            'es_api_key': 'key',
            'es_bearer': 'bearer',
            'aws_region': 'us-east-1',
            'profile': 'default',
            'headers': None,
            'es_host': 'localhost',
            'es_port': 9200,
            'es_url_prefix': 'elasticsearch',
            'es_conn_timeout': 30,
            'send_get_body_as': 'POST',
            'ssl_show_warn': False
        }),
])
def test_build_es_conn_config(es_host, es_port, es_conn_timeout, es_send_get_body_as, ssl_show_warn, es_username,
                              es_password, es_api_key, es_bearer, aws_region, profile, use_ssl, verify_certs,
                              ca_certs, client_cert, client_key, es_url_prefix, expected_data):
    try:
        conf = {}
        if es_host:
            conf['es_host'] = es_host
        if es_port:
            conf['es_port'] = es_port
        if es_conn_timeout:
            conf['es_conn_timeout'] = es_conn_timeout
        if es_send_get_body_as:
            conf['es_send_get_body_as'] = es_send_get_body_as
        if ssl_show_warn != '':
            conf['ssl_show_warn'] = ssl_show_warn
        if es_username:
            conf['es_username'] = es_username
        if es_password:
            conf['es_password'] = es_password
        if es_api_key:
            conf['es_api_key'] = es_api_key
        if es_bearer:
            conf['es_bearer'] = es_bearer
        if aws_region:
            conf['aws_region'] = aws_region
        if profile:
            conf['profile'] = profile
        if use_ssl != '':
            conf['use_ssl'] = use_ssl
        if verify_certs != '':
            conf['verify_certs'] = verify_certs
        if ca_certs:
            conf['ca_certs'] = ca_certs
        if client_cert:
            conf['client_cert'] = client_cert
        if client_key:
            conf['client_key'] = client_key
        if es_url_prefix:
            conf['es_url_prefix'] = es_url_prefix
        actual = build_es_conn_config(conf)
        assert expected_data == actual
    except KeyError:
        assert expected_data


@mock.patch.dict(os.environ, {'ES_USERNAME': 'USER',
                              'ES_PASSWORD': 'PASS',
                              'ES_API_KEY': 'KEY',
                              'ES_BEARER': 'BEARE'})
def test_build_es_conn_config2():
    conf = {}
    conf['es_host'] = 'localhost'
    conf['es_port'] = 9200
    expected = {
        'use_ssl': False,
        'verify_certs': True,
        'ca_certs': None,
        'client_cert': None,
        'client_key': None,
        'http_auth': None,
        'es_username': 'USER',
        'es_password': 'PASS',
        'es_api_key': 'KEY',
        'es_bearer': 'BEARE',
        'aws_region': None,
        'profile': None,
        'headers': None,
        'es_host': 'localhost',
        'es_port': 9200,
        'es_url_prefix': '',
        'es_conn_timeout': 20,
        'send_get_body_as': 'GET',
        'ssl_show_warn': True
    }
    actual = build_es_conn_config(conf)
    assert expected == actual


@pytest.mark.parametrize('es_host, es_port, es_bearer, es_api_key', [
    ('localhost', 9200, '', ''),
    ('localhost', 9200, 'bearer', 'bearer')
])
@mock.patch.dict(os.environ, {'AWS_DEFAULT_REGION': ''})
def test_elasticsearch_client(es_host, es_port, es_bearer, es_api_key):
    conf = {}
    conf['es_host'] = es_host
    conf['es_port'] = es_port
    if es_bearer:
        conf['es_bearer'] = es_bearer
    if es_api_key:
        conf['es_api_key'] = es_api_key
    acutual = elasticsearch_client(conf)
    assert None is not acutual


def test_expand_string_into_dict():
    dictionnary = {'@timestamp': '2021-07-06 01:00:00', 'metric_netfilter.ipv4_dst_cardinality': 401}
    string = 'metadata.source.ip'
    value = '0.0.0.0'

    expand_string_into_dict(dictionnary, string, value)
    assert dictionnary['metadata']['source']['ip'] == value


def test_inc_ts():
    dt = datetime(2021, 7, 6, hour=0, minute=0, second=0)
    actual = inc_ts(dt)
    expected = '2021-07-06T00:00:00.001000Z'
    assert expected == actual


@pytest.mark.parametrize('dt, expected', [
    (None, 0),
    (
        timedelta(
            days=50, seconds=27, microseconds=10, milliseconds=29000, minutes=5, hours=8, weeks=2),
        5558756.00001
    )
])
def test_total_seconds(dt, expected):
    actual = total_seconds(dt)
    assert expected == actual


def test_unixms_to_dt():
    ts = 1626707067
    actual = unixms_to_dt(ts)
    expected = datetime(1970, 1, 19, 19, 51, 47, 67000, tzinfo=tzutc())
    assert expected == actual


def test_dt_to_int():
    dt = datetime(2021, 7, 6, hour=0, minute=0, second=0)
    actual = dt_to_int(dt)
    expected = 1625529600000
    assert expected == actual


def test_format_string():
    target = 0.966666667
    expected_percent_formatting = '0.97'
    assert format_string('%.2f', target) == expected_percent_formatting
    expected_str_formatting = '96.67%'
    assert format_string('{:.2%}', target) == expected_str_formatting


def test_pretty_ts():
    ts = datetime(year=2021, month=8, day=16, hour=16, minute=35, second=5)
    assert '2021-08-16 16:35 UTC' == pretty_ts(ts)
    assert '2021-08-16 16:35 ' == pretty_ts(ts, False)
    assert '2021-08-16 16:35 +0000' == pretty_ts(ts, ts_format='%Y-%m-%d %H:%M %z')
