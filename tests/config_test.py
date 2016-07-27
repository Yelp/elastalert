# -*- coding: utf-8 -*-
import copy
import datetime

import mock
import pytest

import elastalert.alerts
import elastalert.ruletypes
from elastalert.config import get_file_paths
from elastalert.config import load_configuration
from elastalert.config import load_modules
from elastalert.config import load_options
from elastalert.config import load_rules
from elastalert.util import EAException


test_config = {'rules_folder': 'test_folder',
               'run_every': {'minutes': 10},
               'buffer_time': {'minutes': 10},
               'es_host': 'elasticsearch.test',
               'es_port': 12345,
               'writeback_index': 'test_index'}

test_rule = {'es_host': 'test_host',
             'es_port': 12345,
             'name': 'testrule',
             'type': 'spike',
             'spike_height': 2,
             'spike_type': 'up',
             'timeframe': {'minutes': 10},
             'index': 'test_index',
             'query_key': 'testkey',
             'compare_key': 'comparekey',
             'filter': [{'term': {'key': 'value'}}],
             'alert': 'email',
             'use_count_query': True,
             'doc_type': 'blsh',
             'email': 'test@test.test',
             'aggregation': {'hours': 2},
             'include': ['comparekey', '@timestamp']}

test_args = mock.Mock()
test_args.config = 'test_config'
test_args.rule = None


def test_import_rules():
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy['type'] = 'testing.test.RuleType'
    with mock.patch('elastalert.config.yaml_loader') as mock_open:
        mock_open.return_value = test_rule_copy

        # Test that type is imported
        with mock.patch('__builtin__.__import__') as mock_import:
            mock_import.return_value = elastalert.ruletypes
            load_configuration('test_config', test_config)
        assert mock_import.call_args_list[0][0][0] == 'testing.test'
        assert mock_import.call_args_list[0][0][3] == ['RuleType']

        # Test that alerts are imported
        test_rule_copy = copy.deepcopy(test_rule)
        mock_open.return_value = test_rule_copy
        test_rule_copy['alert'] = 'testing2.test2.Alerter'
        with mock.patch('__builtin__.__import__') as mock_import:
            mock_import.return_value = elastalert.alerts
            load_configuration('test_config', test_config)
        assert mock_import.call_args_list[0][0][0] == 'testing2.test2'
        assert mock_import.call_args_list[0][0][3] == ['Alerter']


def test_load_inline_alert_rule():
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy['alert'] = [
        {
            'email': {
                'email': 'foo@bar.baz'
            }
        },
        {
            'email': {
                'email': 'baz@foo.bar'
            }
        }
    ]
    test_config_copy = copy.deepcopy(test_config)
    with mock.patch('elastalert.config.yaml_loader') as mock_open:
        mock_open.side_effect = [test_config_copy, test_rule_copy]
        load_modules(test_rule_copy)
        assert isinstance(test_rule_copy['alert'][0], elastalert.alerts.EmailAlerter)
        assert isinstance(test_rule_copy['alert'][1], elastalert.alerts.EmailAlerter)
        assert 'foo@bar.baz' in test_rule_copy['alert'][0].rule['email']
        assert 'baz@foo.bar' in test_rule_copy['alert'][1].rule['email']


def test_load_rules():
    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)
    with mock.patch('elastalert.config.yaml_loader') as mock_open:
        mock_open.side_effect = [test_config_copy, test_rule_copy]

        with mock.patch('os.listdir') as mock_ls:
            mock_ls.return_value = ['testrule.yaml']
            rules = load_rules(test_args)
            assert isinstance(rules['rules'][0]['type'], elastalert.ruletypes.RuleType)
            assert isinstance(rules['rules'][0]['alert'][0], elastalert.alerts.Alerter)
            assert isinstance(rules['rules'][0]['timeframe'], datetime.timedelta)
            assert isinstance(rules['run_every'], datetime.timedelta)
            for included_key in ['comparekey', 'testkey', '@timestamp']:
                assert included_key in rules['rules'][0]['include']

            # Assert include doesn't contain duplicates
            assert rules['rules'][0]['include'].count('@timestamp') == 1
            assert rules['rules'][0]['include'].count('comparekey') == 1


def test_load_default_host_port():
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy.pop('es_host')
    test_rule_copy.pop('es_port')
    test_config_copy = copy.deepcopy(test_config)
    with mock.patch('elastalert.config.yaml_loader') as mock_open:
        mock_open.side_effect = [test_config_copy, test_rule_copy]

        with mock.patch('os.listdir') as mock_ls:
            mock_ls.return_value = ['testrule.yaml']
            rules = load_rules(test_args)

            # Assert include doesn't contain duplicates
            assert rules['es_port'] == 12345
            assert rules['es_host'] == 'elasticsearch.test'


def test_compound_query_key():
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy.pop('use_count_query')
    test_rule_copy['query_key'] = ['field1', 'field2']
    load_options(test_rule_copy, test_config)
    assert 'field1' in test_rule_copy['include']
    assert 'field2' in test_rule_copy['include']
    assert test_rule_copy['query_key'] == 'field1,field2'
    assert test_rule_copy['compound_query_key'] == ['field1', 'field2']


def test_raises_on_missing_config():
    optional_keys = ('aggregation', 'use_count_query', 'query_key', 'compare_key', 'filter', 'include', 'es_host', 'es_port')
    test_rule_copy = copy.deepcopy(test_rule)
    for key in test_rule_copy.keys():
        test_rule_copy = copy.deepcopy(test_rule)
        test_config_copy = copy.deepcopy(test_config)
        test_rule_copy.pop(key)

        # Non required keys
        if key in optional_keys:
            continue

        with mock.patch('elastalert.config.yaml_loader') as mock_open:
            mock_open.side_effect = [test_config_copy, test_rule_copy]
            with mock.patch('os.listdir') as mock_ls:
                mock_ls.return_value = ['testrule.yaml']
                with pytest.raises(EAException):
                    load_rules(test_args)


def test_raises_on_bad_generate_kibana_filters():
    test_rule['generate_kibana_link'] = True
    bad_filters = [[{'not': {'terms': {'blah': 'blah'}}}],
                   [{'terms': {'blah': 'blah'}}],
                   [{'query': {'not_querystring': 'this:that'}}],
                   [{'query': {'wildcard': 'this*that'}}],
                   [{'blah': 'blah'}]]
    good_filters = [[{'term': {'field': 'value'}}],
                    [{'not': {'term': {'this': 'that'}}}],
                    [{'not': {'query': {'query_string': {'query': 'this:that'}}}}],
                    [{'query': {'query_string': {'query': 'this:that'}}}],
                    [{'range': {'blah': {'from': 'a', 'to': 'b'}}}],
                    [{'not': {'range': {'blah': {'from': 'a', 'to': 'b'}}}}]]

    # Test that all the good filters work, but fail with a bad filter added
    for good in good_filters:
        test_rule_copy = copy.deepcopy(test_rule)
        test_rule_copy['filter'] = good
        with mock.patch('elastalert.config.yaml_loader') as mock_open:
            mock_open.return_value = test_rule_copy
            load_configuration('blah', test_config)
            for bad in bad_filters:
                test_rule_copy['filter'] = good + bad
                with pytest.raises(EAException):
                    load_configuration('blah', test_config)


def test_get_file_paths_recursive():
    conf = {'scan_subdirectories': True, 'rules_folder': 'root'}
    walk_paths = (('root', ('folder_a', 'folder_b'), ('rule.yaml',)),
                  ('root/folder_a', (), ('a.yaml', 'ab.yaml')),
                  ('root/folder_b', (), ('b.yaml',)))
    with mock.patch('os.walk') as mock_walk:
        mock_walk.return_value = walk_paths
        paths = get_file_paths(conf)

    assert 'root/rule.yaml' in paths
    assert 'root/folder_a/a.yaml' in paths
    assert 'root/folder_a/ab.yaml' in paths
    assert 'root/folder_b/b.yaml' in paths
    assert len(paths) == 4


def test_get_file_paths():
    # Check for no subdirectory
    conf = {'scan_subdirectories': False, 'rules_folder': 'root'}
    files = ['badfile', 'a.yaml', 'b.yaml']

    with mock.patch('os.listdir') as mock_list:
        with mock.patch('os.path.isfile') as mock_path:
            mock_path.return_value = True
            mock_list.return_value = files
            paths = get_file_paths(conf)

    assert 'root/a.yaml' in paths
    assert 'root/b.yaml' in paths
    assert len(paths) == 2
