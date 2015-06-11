import copy
import json

from elastalert.kibana import add_filter
from elastalert.kibana import dashboard_temp
from elastalert.kibana import filters_from_dashboard
from elastalert.kibana import kibana4_dashboard_link


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
        }
      },
      "ids": [
        0,
        1,
        2
      ]
    }
  }
}'''
test_dashboard = json.loads(test_dashboard)


def test_filters_from_dashboard():
    filters = filters_from_dashboard(test_dashboard)
    assert {'term': {'_log_type': '"active_directory"'}} in filters
    assert {'query': {'query_string': {'query': 'ad.security_auditing_code:4740'}}} in filters


def test_add_filter():
    basic_filter = {"term": {"this": "that"}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, basic_filter)
    assert db['services']['filter']['list']['1'] == {'field': 'this', 'alias': '', 'mandate': 'must', 'active': True, 'query': '"that"', 'type': 'field', 'id': 1}

    list_filter = {"term": {"this": ["that", "those"]}}
    db = copy.deepcopy(dashboard_temp)
    add_filter(db, list_filter)
    assert db['services']['filter']['list']['1'] == {'field': 'this', 'alias': '', 'mandate': 'must', 'active': True, 'query': '("that" AND "those")', 'type': 'field', 'id': 1}


def test_url_encoded():
    url = kibana4_dashboard_link('example.com/#/Dashboard', '2015-01-01T00:00:00Z', '2017-01-01T00:00:00Z')
    assert not any([special_char in url for special_char in ["',\":;?&=()"]])
