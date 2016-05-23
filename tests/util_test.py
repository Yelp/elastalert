# -*- coding: utf-8 -*-
from elastalert.util import lookup_es_key, set_es_key, add_raw_postfix


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
            'user': 'jimmay'
        }
    }

    assert lookup_es_key(record, 'Fields.ts') is None


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
    assert add_raw_postfix('foo') == expected
    assert add_raw_postfix('foo.raw') == expected
