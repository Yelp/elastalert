# -*- coding: utf-8 -*-
import datetime
import json
import time

import dateutil
import pytest

import elastalert.create_index
import elastalert.elastalert
from elastalert import ElasticSearchClient
from elastalert.util import build_es_conn_config
from tests.conftest import ea  # noqa: F401

test_index = 'test_index'

es_host = '127.0.0.1'
es_port = 9200
es_timeout = 10


@pytest.fixture
def es_client():
    es_conn_config = build_es_conn_config({'es_host': es_host, 'es_port': es_port, 'es_conn_timeout': es_timeout})
    return ElasticSearchClient(es_conn_config)


@pytest.mark.elasticsearch
class TestElasticsearch(object):
    # TODO perform teardown removing data inserted into Elasticsearch
    # Warning!!!: Test class is not erasing its testdata on the Elasticsearch server.
    # This is not a problem as long as the data is manually removed or the test environment
    # is torn down after the test run(eg. running tests in a test environment such as Travis)
    def test_create_indices(self, es_client):
        elastalert.create_index.create_index_mappings(es_client=es_client, ea_index=test_index)
        indices_mappings = es_client.indices.get_mapping(test_index + '*')
        print(('-' * 50))
        print((json.dumps(indices_mappings, indent=2)))
        print(('-' * 50))
        if es_client.is_atleastsix():
            assert test_index in indices_mappings
            assert test_index + '_error' in indices_mappings
            assert test_index + '_status' in indices_mappings
            assert test_index + '_silence' in indices_mappings
            assert test_index + '_past' in indices_mappings
        else:
            assert 'elastalert' in indices_mappings[test_index]['mappings']
            assert 'elastalert_error' in indices_mappings[test_index]['mappings']
            assert 'elastalert_status' in indices_mappings[test_index]['mappings']
            assert 'silence' in indices_mappings[test_index]['mappings']
            assert 'past_elastalert' in indices_mappings[test_index]['mappings']

    @pytest.mark.usefixtures("ea")
    def test_aggregated_alert(self, ea, es_client):  # noqa: F811
        match_timestamp = datetime.datetime.now(tz=dateutil.tz.tzutc()).replace(microsecond=0) + datetime.timedelta(
            days=1)
        ea.rules[0]['aggregate_by_match_time'] = True
        match = {'@timestamp': match_timestamp,
                 'num_hits': 0,
                 'num_matches': 3
                 }
        ea.writeback_es = es_client
        res = ea.add_aggregated_alert(match, ea.rules[0])
        if ea.writeback_es.is_atleastsix():
            assert res['result'] == 'created'
        else:
            assert res['created'] is True
        # Make sure added data is available for querying
        time.sleep(2)
        # Now lets find the pending aggregated alert
        assert ea.find_pending_aggregate_alert(ea.rules[0])

    @pytest.mark.usefixtures("ea")
    def test_silenced(self, ea, es_client):  # noqa: F811
        until_timestamp = datetime.datetime.now(tz=dateutil.tz.tzutc()).replace(microsecond=0) + datetime.timedelta(
            days=1)
        ea.writeback_es = es_client
        res = ea.set_realert(ea.rules[0]['name'], until_timestamp, 0)
        if ea.writeback_es.is_atleastsix():
            assert res['result'] == 'created'
        else:
            assert res['created'] is True
        # Make sure added data is available for querying
        time.sleep(2)
        # Force lookup in elasticsearch
        ea.silence_cache = {}
        # Now lets check if our rule is reported as silenced
        assert ea.is_silenced(ea.rules[0]['name'])

    @pytest.mark.usefixtures("ea")
    def test_get_hits(self, ea, es_client):  # noqa: F811
        start = datetime.datetime.now(tz=dateutil.tz.tzutc()).replace(microsecond=0)
        end = start + datetime.timedelta(days=1)
        ea.current_es = es_client
        if ea.current_es.is_atleastfive():
            ea.rules[0]['five'] = True
        else:
            ea.rules[0]['five'] = False
        ea.thread_data.current_es = ea.current_es
        hits = ea.get_hits(ea.rules[0], start, end, test_index)

        assert isinstance(hits, list)
