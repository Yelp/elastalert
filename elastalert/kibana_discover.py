# -*- coding: utf-8 -*-
# flake8: noqa
import datetime
import logging
import json
import os.path
import prison
import urllib.parse

from .util import EAException
from .util import elastalert_logger
from .util import lookup_es_key
from .util import ts_add

kibana_default_timedelta = datetime.timedelta(minutes=10)

kibana5_kibana6_versions = frozenset(['5.6', '6.0', '6.1', '6.2', '6.3', '6.4', '6.5', '6.6', '6.7', '6.8'])
kibana7_versions = frozenset(['7.0', '7.1', '7.2', '7.3', '7.4', '7.5', '7.6', '7.7', '7.8', '7.9', '7.10', '7.11', '7.12', '7.13', '7.14'])

def generate_kibana_discover_url(rule, match):
    ''' Creates a link for a kibana discover app. '''

    discover_app_url = rule.get('kibana_discover_app_url')
    if not discover_app_url:
        elastalert_logger.warning(
            'Missing kibana_discover_app_url for rule %s' % (
                rule.get('name', '<MISSING NAME>')
            )
        )
        return None

    kibana_version = rule.get('kibana_discover_version')
    if not kibana_version:
        elastalert_logger.warning(
            'Missing kibana_discover_version for rule %s' % (
                rule.get('name', '<MISSING NAME>')
            )
        )
        return None

    index = rule.get('kibana_discover_index_pattern_id')
    if not index:
        elastalert_logger.warning(
            'Missing kibana_discover_index_pattern_id for rule %s' % (
                rule.get('name', '<MISSING NAME>')
            )
        )
        return None

    columns = rule.get('kibana_discover_columns', ['_source'])
    filters = rule.get('filter', [])

    if 'query_key' in rule:
        query_keys = rule.get('compound_query_key', [rule['query_key']])
    else:
        query_keys = []

    timestamp = lookup_es_key(match, rule['timestamp_field'])
    timeframe = rule.get('timeframe', kibana_default_timedelta)
    from_timedelta = rule.get('kibana_discover_from_timedelta', timeframe)
    from_time = ts_add(timestamp, -from_timedelta)
    to_timedelta = rule.get('kibana_discover_to_timedelta', timeframe)
    to_time = ts_add(timestamp, to_timedelta)

    if kibana_version in kibana5_kibana6_versions:
        globalState = kibana6_disover_global_state(from_time, to_time)
        appState = kibana_discover_app_state(index, columns, filters, query_keys, match)

    elif kibana_version in kibana7_versions:
        globalState = kibana7_disover_global_state(from_time, to_time)
        appState = kibana_discover_app_state(index, columns, filters, query_keys, match)

    else:
        elastalert_logger.warning(
            'Unknown kibana discover application version %s for rule %s' % (
                kibana_version,
                rule.get('name', '<MISSING NAME>')
            )
        )
        return None

    return "%s?_g=%s&_a=%s" % (
        os.path.expandvars(discover_app_url),
        urllib.parse.quote(globalState),
        urllib.parse.quote(appState)
    )


def kibana6_disover_global_state(from_time, to_time):
    return prison.dumps( {
        'refreshInterval': {
            'pause': True,
            'value': 0
        },
        'time': {
            'from': from_time,
            'mode': 'absolute',
            'to': to_time
        }
    } )


def kibana7_disover_global_state(from_time, to_time):
    return prison.dumps( {
        'filters': [],
        'refreshInterval': {
            'pause': True,
            'value': 0
        },
        'time': {
            'from': from_time,
            'to': to_time
        }
    } )


def kibana_discover_app_state(index, columns, filters, query_keys, match):
    app_filters = []

    if filters:
        bool_filter = { 'must': filters }
        app_filters.append( {
            '$state': {
                'store': 'appState'
            },
            'bool': bool_filter,
            'meta': {
                'alias': 'filter',
                'disabled': False,
                'index': index,
                'key': 'bool',
                'negate': False,
                'type': 'custom',
                'value': json.dumps(bool_filter, separators=(',', ':'))
            },
        } )

    for query_key in query_keys:
        query_value = lookup_es_key(match, query_key)

        if query_value is None:
            app_filters.append( {
                '$state': {
                    'store': 'appState'
                },
                'exists': {
                    'field': query_key
                },
                'meta': {
                    'alias': None,
                    'disabled': False,
                    'index': index,
                    'key': query_key,
                    'negate': True,
                    'type': 'exists',
                    'value': 'exists'
                }
            } )

        else:
            app_filters.append( {
                '$state': {
                    'store': 'appState'
                },
                'meta': {
                    'alias': None,
                    'disabled': False,
                    'index': index,
                    'key': query_key,
                    'negate': False,
                    'params': {
                        'query': query_value,
                        'type': 'phrase'
                    },
                    'type': 'phrase',
                    'value': str(query_value)
                },
                'query': {
                    'match': {
                        query_key: {
                            'query': query_value,
                            'type': 'phrase'
                        }
                    }
                }
            } )

    return prison.dumps( {
        'columns': columns,
        'filters': app_filters,
        'index': index,
        'interval': 'auto'
    } )
