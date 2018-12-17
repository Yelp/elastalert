# -*- coding: utf-8 -*-
from datetime import datetime
from datetime import timedelta

import mock
import pytest
from dateutil.parser import parse as dt

from elastalert.util import add_raw_postfix
from elastalert.util import format_index
from elastalert.util import lookup_es_key
from elastalert.util import parse_deadline
from elastalert.util import parse_duration
from elastalert.util import replace_dots_in_field_names
from elastalert.util import resolve_string
from elastalert.util import set_es_key


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
