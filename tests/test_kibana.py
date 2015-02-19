import json
from elastalert.kibana import filters_from_dashboard


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
    expected_filters = [{'term': {'_log_type': '"active_directory"'}}, {'query': {'query_string': {'query': 'ad.security_auditing_code:4740'}}}]
    assert filters == expected_filters
