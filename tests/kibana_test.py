import copy
import json

from elastalert.kibana import add_filter
from elastalert.kibana import dashboard_temp
from elastalert.kibana import filters_from_dashboard
from elastalert.kibana import kibana4_dashboard_link
from elastalert.util import EAException


# Dashboard schema with only filters section
test_dashboard = '''{
  "title": "AD Lock Outs",
  "services": {
    "filter": {
      "list": {
        "0": {
          "type": "time",
          "field": "@timestamp",
          "from": "now-7d",
          "to": "now",
          "mandate": "must",
          "active": true,
          "alias": "",
          "id": 0
        },
        "1": {
          "type": "field",
          "field": "_log_type",
          "query": "\\"active_directory\\"",
          "mandate": "must",
          "active": true,
          "alias": "",
          "id": 1
        },
        "2": {
          "type": "querystring",
          "query": "ad.security_auditing_code:4740",
          "mandate": "must",
          "active": true,
          "alias": "",
          "id": 2
        },
        "3": {
          "type": "range",
          "field": "@timestamp",
          "mandate": "must",
          "active": true,
          "alias": "",
          "from": "2014-09-27T12:34:45Z",
          "to": "2014-09-26T12:34:45Z",
          "id": 3
        },
        "4": {
          "field": "@timestamp",
          "alias": "",
          "mandate": "mustNot",
          "active": true,
          "query": "that",
          "type": "field",
          "id": 4
        },
        "5": {
          "field": "@timestamp",
          "alias": "",
          "mandate": "either",
          "active": true,
          "query": "that",
          "type": "field",
          "id": 5
        }
      },
      "ids": [
        0,
        1,
        2,
        3,
        4,
        5
      ]
    }
  }
}'''
test_dashboard = json.loads(test_dashboard)

test_dashboard2 = '''{
  "title": "AD Lock Outs",
  "services": {
    "filter": {
      "list": {
        "0": {
          "type": "time",
          "field": "@timestamp",
          "from": "now-7d",
          "to": "now",
          "mandate": "must",
          "active": true,
          "alias": "",
          "id": 0
        },
        "1": {
          "type": "field",
          "field": "_log_type",
          "query": "\\"active_directory\\"",
          "mandate": "must",
          "active": true,
          "alias": "",
          "id": 1
        }
      },
      "ids": [
        0,
        1
      ]
    }
  }
}'''
test_dashboard2 = json.loads(test_dashboard2)


def test_filters_from_dashboard():
    filters = filters_from_dashboard(test_dashboard)
    assert {'term': {'_log_type': '"active_directory"'}} in filters
    assert {'query': {'query_string': {'query': 'ad.security_auditing_code:4740'}}} in filters
    assert {'range': {'@timestamp': {'from': '2014-09-27T12:34:45Z', 'to': '2014-09-26T12:34:45Z'}}} in filters
    assert {'not': {'term': {'@timestamp': 'that'}}} in filters
    assert {'or': [{'term': {'@timestamp': 'that'}}]} in filters


def test_filters_from_dashboard2():
    filters = filters_from_dashboard(test_dashboard2)
    assert {'term': {'_log_type': '"active_directory"'}} in filters


def test_add_filter():
    basic_filter = {"term": {"this": "that"}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, basic_filter)
    assert db['services']['filter']['list']['1'] == {
        'field': 'this',
        'alias': '',
        'mandate': 'must',
        'active': True,
        'query': '"that"',
        'type': 'field',
        'id': 1
    }

    list_filter = {"term": {"this": ["that", "those"]}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, list_filter)
    assert db['services']['filter']['list']['1'] == {
        'field': 'this',
        'alias': '',
        'mandate': 'must',
        'active': True,
        'query': '("that" AND "those")',
        'type': 'field',
        'id': 1
    }

    not_filter = {'not': {'term': {'this': 'that'}}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, not_filter)
    assert db['services']['filter']['list']['1'] == {
        'field': 'this',
        'alias': '',
        'mandate': 'mustNot',
        'active': True,
        'query': '"that"',
        'type': 'field',
        'id': 1
    }

    START_TIMESTAMP = '2014-09-26T12:34:45Z'
    END_TIMESTAMP = '2014-09-27T12:34:45Z'
    range_filter = {'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, range_filter)
    assert db['services']['filter']['list']['1'] == {
      'field': '@timestamp',
      'alias': '',
      'mandate': 'must',
      'active': True,
      'lte': '2014-09-27T12:34:45Z',
      'gt': '2014-09-26T12:34:45Z',
      'type': 'range',
      'id': 1
    }

    query_filter = {'query': {'wildcard': 'this*that'}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, query_filter)
    assert db['services']['filter']['list']['1'] == {
      'alias': '',
      'mandate': 'must',
      'active': True,
      'id': 1
    }

    query_string_filter = {'query': {'query_string': {'query': 'ad.security_auditing_code:4740'}}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, query_string_filter)
    assert db['services']['filter']['list']['1'] == {
      'alias': '',
      'mandate': 'must',
      'active': True,
      'query': 'ad.security_auditing_code:4740',
      'type': 'querystring',
      'id': 1
    }

    try:
        error_filter = {'bool': {'must': [{'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}]}}
        db = copy.deepcopy(dashboard_temp)
        add_filter(db, error_filter)
    except EAException as ea:
        excepted = "Could not parse filter {'bool': {'must': [{'range': {'@timestamp': "
        excepted += "{'lte': '2014-09-27T12:34:45Z', 'gt': '2014-09-26T12:34:45Z'}}}]}} for Kibana"
        assert excepted == str(ea)


def test_url_encoded():
    url = kibana4_dashboard_link('example.com/#/Dashboard', '2015-01-01T00:00:00Z', '2017-01-01T00:00:00Z')
    assert not any([special_char in url for special_char in ["',\":;?&=()"]])


def test_url_env_substitution(environ):
    environ.update({
        'KIBANA_HOST': 'kibana',
        'KIBANA_PORT': '5601',
    })
    url = kibana4_dashboard_link(
        'http://$KIBANA_HOST:$KIBANA_PORT/#/Dashboard',
        '2015-01-01T00:00:00Z',
        '2017-01-01T00:00:00Z',
    )
    assert url.startswith('http://kibana:5601/#/Dashboard')
