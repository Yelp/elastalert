# -*- coding: utf-8 -*-
import datetime
import json
from unittest import mock
from jinja2 import Template

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.util import ts_add


class mock_rule:
    def get_match_str(self, event):
        return str(event)


def test_basic_match_string(ea):
    ea.rules[0]['top_count_keys'] = ['username']
    match = {'@timestamp': '1918-01-17', 'field': 'value', 'top_events_username': {'bob': 10, 'mallory': 5}}
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'anytest' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'bob: 10' in alert_text
    assert 'field: value' in alert_text

    # Non serializable objects don't cause errors
    match['non-serializable'] = {open: 10}
    alert_text = str(BasicMatchString(ea.rules[0], match))

    # unicode objects dont cause errors
    match['snowman'] = '☃'
    alert_text = str(BasicMatchString(ea.rules[0], match))

    # Pretty printed objects
    match.pop('non-serializable')
    match['object'] = {'this': {'that': [1, 2, "3"]}}
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert '"this": {\n        "that": [\n            1,\n            2,\n            "3"\n        ]\n    }' in alert_text

    ea.rules[0]['alert_text'] = 'custom text'
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'anytest' not in alert_text

    ea.rules[0]['alert_text_type'] = 'alert_text_only'
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' not in alert_text
    assert 'username' not in alert_text
    assert 'field: value' not in alert_text

    ea.rules[0]['alert_text_type'] = 'exclude_fields'
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'field: value' not in alert_text


def test_kibana(ea):
    rule = {'filter': [{'query': {'query_string': {'query': 'xy:z'}}}],
            'name': 'Test rule!',
            'es_host': 'test.testing',
            'es_port': 12345,
            'timeframe': datetime.timedelta(hours=1),
            'index': 'logstash-test',
            'include': ['@timestamp'],
            'timestamp_field': '@timestamp'}
    match = {'@timestamp': '2014-10-10T00:00:00'}
    with mock.patch("elastalert.elastalert.elasticsearch_client") as mock_es:
        mock_create = mock.Mock(return_value={'_id': 'ABCDEFGH'})
        mock_es_inst = mock.Mock()
        mock_es_inst.index = mock_create
        mock_es_inst.host = 'test.testing'
        mock_es_inst.port = 12345
        mock_es.return_value = mock_es_inst
        link = ea.generate_kibana_db(rule, match)

    assert 'http://test.testing:12345/_plugin/kibana/#/dashboard/temp/ABCDEFGH' == link

    # Name and index
    dashboard = json.loads(mock_create.call_args_list[0][1]['body']['dashboard'])
    assert dashboard['index']['default'] == 'logstash-test'
    assert 'Test rule!' in dashboard['title']

    # Filters and time range
    filters = dashboard['services']['filter']['list']
    assert 'xy:z' in filters['1']['query']
    assert filters['1']['type'] == 'querystring'
    time_range = filters['0']
    assert time_range['from'] == ts_add(match['@timestamp'], -rule['timeframe'])
    assert time_range['to'] == ts_add(match['@timestamp'], datetime.timedelta(minutes=10))

    # Included fields active in table
    assert dashboard['rows'][1]['panels'][0]['fields'] == ['@timestamp']


def test_alert_text_kw(ea):
    rule = ea.rules[0].copy()
    rule['alert_text'] = '{field} at {time}'
    rule['alert_text_kw'] = {
        '@timestamp': 'time',
        'field': 'field',
    }
    match = {'@timestamp': '1918-01-17', 'field': 'value'}
    alert_text = str(BasicMatchString(rule, match))
    body = '{field} at {@timestamp}'.format(**match)
    assert body in alert_text


def test_alert_text_global_substitution(ea):
    rule = ea.rules[0].copy()
    rule['owner'] = 'the owner from rule'
    rule['priority'] = 'priority from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Priority: {0}; Owner: {1}; Abc: {2}'
    rule['alert_text_args'] = ['priority', 'owner', 'abc']

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }

    alert_text = str(BasicMatchString(rule, match))
    assert 'Priority: priority from rule' in alert_text
    assert 'Owner: the owner from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_alert_text_kw_global_substitution(ea):
    rule = ea.rules[0].copy()
    rule['foo_rule'] = 'foo from rule'
    rule['owner'] = 'the owner from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Owner: {owner}; Foo: {foo}; Abc: {abc}'
    rule['alert_text_kw'] = {
        'owner': 'owner',
        'foo_rule': 'foo',
        'abc': 'abc',
    }

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }

    alert_text = str(BasicMatchString(rule, match))
    assert 'Owner: the owner from rule' in alert_text
    assert 'Foo: foo from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_alert_text_jinja(ea):
    rule = ea.rules[0].copy()
    rule['foo_rule'] = 'foo from rule'
    rule['owner'] = 'the owner from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Owner: {{owner}}; Foo: {{_data["foo_rule"]}}; Abc: {{abc}}; Xyz: {{_data["xyz"]}}'
    rule['alert_text_type'] = "alert_text_jinja"
    rule['jinja_root_name'] = "_data"
    rule['jinja_template'] = Template(str(rule['alert_text']))

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
        'xyz': 'from match'
    }

    alert_text = str(BasicMatchString(rule, match))
    assert 'Owner: the owner from rule' in alert_text
    assert 'Foo: foo from rule' in alert_text
    assert 'Xyz: from match' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_resolving_rule_references():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'list_of_things': [
            '1',
            '$owner$',
            [
                '11',
                '$owner$',
            ],
        ],
        'nested_dict': {
            'nested_one': '1',
            'nested_owner': '$owner$',
        },
        'resolved_string_reference': '$owner$',
        'resolved_int_reference': '$priority$',
        'unresolved_reference': '$foo$',
    }
    alert = Alerter(rule)
    assert 'the_owner' == alert.rule['resolved_string_reference']
    assert 2 == alert.rule['resolved_int_reference']
    assert '$foo$' == alert.rule['unresolved_reference']
    assert 'the_owner' == alert.rule['list_of_things'][1]
    assert 'the_owner' == alert.rule['list_of_things'][2][1]
    assert 'the_owner' == alert.rule['nested_dict']['nested_owner']


def test_alert_subject_size_limit_no_args():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    alert = Alerter(rule)
    alertSubject = alert.create_custom_title([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
    assert 5 == len(alertSubject)


def test_alert_error():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'name': 'datadog-test-name'
    }
    alert = Alerter(rule)
    try:
        alert.alert([match])
    except NotImplementedError:
        assert True


def test_alert_get_aggregation_summary_text__maximum_width():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    alert = Alerter(rule)
    assert 80 == alert.get_aggregation_summary_text__maximum_width()


def test_alert_subject_size_limit_with_args(ea):
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'Test alert for {0} {1}',
        'alert_subject_args': ['test_term', 'test.term'],
        'alert_subject_max_len': 6
    }
    alert = Alerter(rule)
    alertSubject = alert.create_custom_title([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
    assert 6 == len(alertSubject)


def test_alert_subject_with_jinja():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'Test alert for {{owner}}; field {{field}}; Abc: {{_data["abc"]}}',
        'alert_text_type': "alert_text_jinja",
        'jinja_root_name': "_data"
    }
    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }
    alert = Alerter(rule)
    alertsubject = alert.create_custom_title([match])
    assert "Test alert for the_owner;" in alertsubject
    assert "field field_value;" in alertsubject
    assert "Abc: abc from match" in alertsubject


def test_alert_getinfo():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    alert = Alerter(rule)
    actual_data = alert.get_info()
    expected_data = {'type': 'Unknown'}
    assert expected_data == actual_data
