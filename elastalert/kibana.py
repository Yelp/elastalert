# -*- coding: utf-8 -*-
import urllib

from util import EAException


dashboard_temp = {'editable': True,
                  u'failover': False,
                  u'index': {u'default': u'NO_TIME_FILTER_OR_INDEX_PATTERN_NOT_MATCHED',
                             u'interval': u'none',
                             u'pattern': u'',
                             u'warm_fields': True},
                  u'loader': {u'hide': False,
                              u'load_elasticsearch': True,
                              u'load_elasticsearch_size': 20,
                              u'load_gist': True,
                              u'load_local': True,
                              u'save_default': True,
                              u'save_elasticsearch': True,
                              u'save_gist': False,
                              u'save_local': True,
                              u'save_temp': True,
                              u'save_temp_ttl': u'30d',
                              u'save_temp_ttl_enable': True},
                  u'nav': [{u'collapse': False,
                            u'enable': True,
                            u'filter_id': 0,
                            u'notice': False,
                            u'now': False,
                            u'refresh_intervals': [u'5s',
                                                   u'10s',
                                                   u'30s',
                                                   u'1m',
                                                   u'5m',
                                                   u'15m',
                                                   u'30m',
                                                   u'1h',
                                                   u'2h',
                                                   u'1d'],
                            u'status': u'Stable',
                            u'time_options': [u'5m',
                                              u'15m',
                                              u'1h',
                                              u'6h',
                                              u'12h',
                                              u'24h',
                                              u'2d',
                                              u'7d',
                                              u'30d'],
                            u'timefield': u'@timestamp',
                            u'type': u'timepicker'}],
                  u'panel_hints': True,
                  u'pulldowns': [{u'collapse': False,
                                  u'enable': True,
                                  u'notice': True,
                                  u'type': u'filtering'}],
                  u'refresh': False,
                  u'rows': [{u'collapsable': True,
                             u'collapse': False,
                             u'editable': True,
                             u'height': u'350px',
                             u'notice': False,
                             u'panels': [{u'annotate': {u'enable': False,
                                                        u'field': u'_type',
                                                        u'query': u'*',
                                                        u'size': 20,
                                                        u'sort': [u'_score', u'desc']},
                                          u'auto_int': True,
                                          u'bars': True,
                                          u'derivative': False,
                                          u'editable': True,
                                          u'fill': 3,
                                          u'grid': {u'max': None, u'min': 0},
                                          u'group': [u'default'],
                                          u'interactive': True,
                                          u'interval': u'1m',
                                          u'intervals': [u'auto',
                                                         u'1s',
                                                         u'1m',
                                                         u'5m',
                                                         u'10m',
                                                         u'30m',
                                                         u'1h',
                                                         u'3h',
                                                         u'12h',
                                                         u'1d',
                                                         u'1w',
                                                         u'1M',
                                                         u'1y'],
                                          u'legend': True,
                                          u'legend_counts': True,
                                          u'lines': False,
                                          u'linewidth': 3,
                                          u'mode': u'count',
                                          u'options': True,
                                          u'percentage': False,
                                          u'pointradius': 5,
                                          u'points': False,
                                          u'queries': {u'ids': [0], u'mode': u'all'},
                                          u'resolution': 100,
                                          u'scale': 1,
                                          u'show_query': True,
                                          u'span': 12,
                                          u'spyable': True,
                                          u'stack': True,
                                          u'time_field': u'@timestamp',
                                          u'timezone': u'browser',
                                          u'title': u'Events over time',
                                          u'tooltip': {u'query_as_alias': True,
                                                       u'value_type': u'cumulative'},
                                          u'type': u'histogram',
                                          u'value_field': None,
                                          u'x-axis': True,
                                          u'y-axis': True,
                                          u'y_format': u'none',
                                          u'zerofill': True,
                                          u'zoomlinks': True}],
                             u'title': u'Graph'},
                            {u'collapsable': True,
                             u'collapse': False,
                             u'editable': True,
                             u'height': u'350px',
                             u'notice': False,
                             u'panels': [{u'all_fields': False,
                                          u'editable': True,
                                          u'error': False,
                                          u'field_list': True,
                                          u'fields': [],
                                          u'group': [u'default'],
                                          u'header': True,
                                          u'highlight': [],
                                          u'localTime': True,
                                          u'normTimes': True,
                                          u'offset': 0,
                                          u'overflow': u'min-height',
                                          u'pages': 5,
                                          u'paging': True,
                                          u'queries': {u'ids': [0], u'mode': u'all'},
                                          u'size': 100,
                                          u'sort': [u'@timestamp', u'desc'],
                                          u'sortable': True,
                                          u'span': 12,
                                          u'spyable': True,
                                          u'status': u'Stable',
                                          u'style': {u'font-size': u'9pt'},
                                          u'timeField': u'@timestamp',
                                          u'title': u'All events',
                                          u'trimFactor': 300,
                                          u'type': u'table'}],
                             u'title': u'Events'}],
                  u'services': {u'filter': {u'ids': [0],
                                            u'list': {u'0': {u'active': True,
                                                             u'alias': u'',
                                                             u'field': u'@timestamp',
                                                             u'from': u'now-24h',
                                                             u'id': 0,
                                                             u'mandate': u'must',
                                                             u'to': u'now',
                                                             u'type': u'time'}}},
                                u'query': {u'ids': [0],
                                           u'list': {u'0': {u'alias': u'',
                                                            u'color': u'#7EB26D',
                                                            u'enable': True,
                                                            u'id': 0,
                                                            u'pin': False,
                                                            u'query': u'',
                                                            u'type': u'lucene'}}}},
                  u'style': u'dark',
                  u'title': u'ElastAlert Alert Dashboard'}

kibana4_time_temp = "(refreshInterval:(display:Off,section:0,value:0),time:(from:'%s',mode:absolute,to:'%s'))"


def set_time(dashboard, start, end):
    dashboard['services']['filter']['list']['0']['from'] = start
    dashboard['services']['filter']['list']['0']['to'] = end


def set_index_name(dashboard, name):
    dashboard['index']['default'] = name


def set_timestamp_field(dashboard, field):
    # set the nav timefield if we don't want @timestamp
    dashboard['nav'][0]['timefield'] = field

    # set the time_field for each of our panels
    for row in dashboard.get('rows'):
        for panel in row.get('panels'):
            panel['time_field'] = field

    # set our filter's  time field
    dashboard['services']['filter']['list']['0']['field'] = field


def add_filter(dashboard, es_filter):
    next_id = max(dashboard['services']['filter']['ids']) + 1

    kibana_filter = {'active': True,
                     'alias': '',
                     'id': next_id,
                     'mandate': 'must'}

    if 'not' in es_filter:
        es_filter = es_filter['not']
        kibana_filter['mandate'] = 'mustNot'

    if 'query' in es_filter:
        es_filter = es_filter['query']
        if 'query_string' in es_filter:
            kibana_filter['type'] = 'querystring'
            kibana_filter['query'] = es_filter['query_string']['query']
    elif 'term' in es_filter:
        kibana_filter['type'] = 'field'
        f_field, f_query = es_filter['term'].items()[0]
        # Wrap query in quotes, otherwise certain characters cause Kibana to throw errors
        if isinstance(f_query, basestring):
            f_query = '"%s"' % (f_query.replace('"', '\\"'))
        if isinstance(f_query, list):
            # Escape quotes
            f_query = [item.replace('"', '\\"') for item in f_query]
            # Wrap in quotes
            f_query = ['"%s"' % (item) for item in f_query]
            # Convert into joined query
            f_query = '(%s)' % (' AND '.join(f_query))
        kibana_filter['field'] = f_field
        kibana_filter['query'] = f_query
    elif 'range' in es_filter:
        kibana_filter['type'] = 'range'
        f_field, f_range = es_filter['range'].items()[0]
        kibana_filter['field'] = f_field
        kibana_filter.update(f_range)
    else:
        raise EAException("Could not parse filter %s for Kibana" % (es_filter))

    dashboard['services']['filter']['ids'].append(next_id)
    dashboard['services']['filter']['list'][str(next_id)] = kibana_filter


def set_name(dashboard, name):
    dashboard['title'] = name


def set_included_fields(dashboard, fields):
    dashboard['rows'][1]['panels'][0]['fields'] = list(set(fields))


def filters_from_dashboard(db):
    filters = db['services']['filter']['list']
    config_filters = []
    or_filters = []
    for filter in filters.values():
        filter_type = filter['type']
        if filter_type == 'time':
            continue

        if filter_type == 'querystring':
            config_filter = {'query': {'query_string': {'query': filter['query']}}}

        if filter_type == 'field':
            config_filter = {'term': {filter['field']: filter['query']}}

        if filter_type == 'range':
            config_filter = {'range': {filter['field']: {'from': filter['from'], 'to': filter['to']}}}

        if filter['mandate'] == 'mustNot':
            config_filter = {'not': config_filter}

        if filter['mandate'] == 'either':
            or_filters.append(config_filter)
        else:
            config_filters.append(config_filter)

    if or_filters:
        config_filters.append({'or': or_filters})

    return config_filters


def kibana4_dashboard_link(dashboard, starttime, endtime):
    time_settings = kibana4_time_temp % (starttime, endtime)
    time_settings = urllib.quote(time_settings)
    return "%s?_g=%s" % (dashboard, time_settings)
