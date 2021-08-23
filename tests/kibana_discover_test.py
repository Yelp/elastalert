# -*- coding: utf-8 -*-
from datetime import timedelta
import pytest

from elastalert.kibana_discover import generate_kibana_discover_url


@pytest.mark.parametrize("kibana_version", ['5.6', '6.0', '6.1', '6.2', '6.3', '6.4', '6.5', '6.6', '6.7', '6.8'])
def test_generate_kibana_discover_url_with_kibana_5x_and_6x(kibana_version):
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': kibana_version,
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


@pytest.mark.parametrize("kibana_version", [
    '7.0',
    '7.1',
    '7.2',
    '7.3',
    '7.4',
    '7.5',
    '7.6',
    '7.7',
    '7.8',
    '7.9',
    '7.10',
    '7.11',
    '7.12',
    '7.13',
    '7.14'
])
def test_generate_kibana_discover_url_with_kibana_7x(kibana_version):
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': kibana_version,
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'filters%3A%21%28%29%2C'
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_missing_kibana_discover_version():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_index_pattern_id': 'logs',
            'timestamp_field': 'timestamp',
            'name': 'test'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    assert url is None


def test_generate_kibana_discover_url_with_missing_kibana_discover_app_url():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs',
            'timestamp_field': 'timestamp',
            'name': 'test'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    assert url is None


def test_generate_kibana_discover_url_with_missing_kibana_discover_index_pattern_id():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'timestamp_field': 'timestamp',
            'name': 'test'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    assert url is None


def test_generate_kibana_discover_url_with_invalid_kibana_version():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '4.5',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    assert url is None


def test_generate_kibana_discover_url_with_kibana_discover_app_url_env_substitution(environ):
    environ.update({
        'KIBANA_HOST': 'kibana',
        'KIBANA_PORT': '5601',
    })
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://$KIBANA_HOST:$KIBANA_PORT/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_from_timedelta():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '7.14',
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'kibana_discover_from_timedelta': timedelta(hours=1),
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T04:00:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'filters%3A%21%28%29%2C'
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T03%3A00%3A00Z%27%2C'
        + 'to%3A%272019-09-01T04%3A10%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_from_timedelta_and_timeframe():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '7.14',
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'kibana_discover_from_timedelta': timedelta(hours=1),
            'timeframe': timedelta(minutes=20),
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T04:00:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'filters%3A%21%28%29%2C'
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T03%3A00%3A00Z%27%2C'
        + 'to%3A%272019-09-01T04%3A20%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_to_timedelta():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '7.14',
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'kibana_discover_to_timedelta': timedelta(hours=1),
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T04:00:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'filters%3A%21%28%29%2C'
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T03%3A50%3A00Z%27%2C'
        + 'to%3A%272019-09-01T05%3A00%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_to_timedelta_and_timeframe():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '7.14',
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'kibana_discover_to_timedelta': timedelta(hours=1),
            'timeframe': timedelta(minutes=20),
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T04:00:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'filters%3A%21%28%29%2C'
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T03%3A40%3A00Z%27%2C'
        + 'to%3A%272019-09-01T05%3A00%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_timeframe():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '7.14',
            'kibana_discover_index_pattern_id': 'd6cabfb6-aaef-44ea-89c5-600e9a76991a',
            'timeframe': timedelta(minutes=20),
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T04:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'filters%3A%21%28%29%2C'
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T04%3A10%3A00Z%27%2C'
        + 'to%3A%272019-09-01T04%3A50%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3Ad6cabfb6-aaef-44ea-89c5-600e9a76991a%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_custom_columns():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'kibana_discover_columns': ['level', 'message'],
            'timestamp_field': 'timestamp'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28level%2Cmessage%29%2C'
        + 'filters%3A%21%28%29%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_single_filter():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'filter': [
                {'term': {'level': 30}}
            ]
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'bool%3A%28must%3A%21%28%28term%3A%28level%3A30%29%29%29%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3Afilter%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Abool%2C'
        + 'negate%3A%21f%2C'
        + 'type%3Acustom%2C'
        + 'value%3A%27%7B%22must%22%3A%5B%7B%22term%22%3A%7B%22level%22%3A30%7D%7D%5D%7D%27'
        + '%29'  # meta end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_multiple_filters():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': '90943e30-9a47-11e8-b64d-95841ca0b247',
            'timestamp_field': 'timestamp',
            'filter': [
                {'term': {'app': 'test'}},
                {'term': {'level': 30}}
            ]
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'bool%3A%28must%3A%21%28%28term%3A%28app%3Atest%29%29%2C%28term%3A%28level%3A30%29%29%29%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3Afilter%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%2790943e30-9a47-11e8-b64d-95841ca0b247%27%2C'
        + 'key%3Abool%2C'
        + 'negate%3A%21f%2C'
        + 'type%3Acustom%2C'
        + 'value%3A%27%7B%22must%22%3A%5B'  # value start
        + '%7B%22term%22%3A%7B%22app%22%3A%22test%22%7D%7D%2C%7B%22term%22%3A%7B%22level%22%3A30%7D%7D'
        + '%5D%7D%27'  # value end
        + '%29'  # meta end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%2790943e30-9a47-11e8-b64d-95841ca0b247%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_int_query_key():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'query_key': 'geo.dest'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z',
            'geo.dest': 200
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Ageo.dest%2C'
        + 'negate%3A%21f%2C'
        + 'params%3A%28query%3A200%2C'  # params start
        + 'type%3Aphrase'
        + '%29%2C'  # params end
        + 'type%3Aphrase%2C'
        + 'value%3A%27200%27'
        + '%29%2C'  # meta end
        + 'query%3A%28'  # query start
        + 'match%3A%28'  # match start
        + 'geo.dest%3A%28'  # reponse start
        + 'query%3A200%2C'
        + 'type%3Aphrase'
        + '%29'  # geo.dest end
        + '%29'  # match end
        + '%29'  # query end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_str_query_key():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'query_key': 'geo.dest'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z',
            'geo': {
                'dest': 'ok'
            }
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Ageo.dest%2C'
        + 'negate%3A%21f%2C'
        + 'params%3A%28query%3Aok%2C'  # params start
        + 'type%3Aphrase'
        + '%29%2C'  # params end
        + 'type%3Aphrase%2C'
        + 'value%3Aok'
        + '%29%2C'  # meta end
        + 'query%3A%28'  # query start
        + 'match%3A%28'  # match start
        + 'geo.dest%3A%28'  # geo.dest start
        + 'query%3Aok%2C'
        + 'type%3Aphrase'
        + '%29'  # geo.dest end
        + '%29'  # match end
        + '%29'  # query end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_null_query_key_value():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'query_key': 'status'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z',
            'status': None
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'exists%3A%28field%3Astatus%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Astatus%2C'
        + 'negate%3A%21t%2C'
        + 'type%3Aexists%2C'
        + 'value%3Aexists'
        + '%29'  # meta end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_missing_query_key_value():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'query_key': 'status'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'exists%3A%28field%3Astatus%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Astatus%2C'
        + 'negate%3A%21t%2C'
        + 'type%3Aexists%2C'
        + 'value%3Aexists'
        + '%29'  # meta end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_compound_query_key():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'compound_query_key': ['geo.src', 'geo.dest'],
            'query_key': 'geo.src,geo.dest'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z',
            'geo': {
                'src': 'CA',
                'dest': 'US'
            }
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # geo.src filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Ageo.src%2C'
        + 'negate%3A%21f%2C'
        + 'params%3A%28query%3ACA%2C'  # params start
        + 'type%3Aphrase'
        + '%29%2C'  # params end
        + 'type%3Aphrase%2C'
        + 'value%3ACA'
        + '%29%2C'  # meta end
        + 'query%3A%28'  # query start
        + 'match%3A%28'  # match start
        + 'geo.src%3A%28'  # reponse start
        + 'query%3ACA%2C'
        + 'type%3Aphrase'
        + '%29'  # geo.src end
        + '%29'  # match end
        + '%29'  # query end
        + '%29%2C'  # geo.src filter end

        + '%28'  # geo.dest filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Ageo.dest%2C'
        + 'negate%3A%21f%2C'
        + 'params%3A%28query%3AUS%2C'  # params start
        + 'type%3Aphrase'
        + '%29%2C'  # params end
        + 'type%3Aphrase%2C'
        + 'value%3AUS'
        + '%29%2C'  # meta end
        + 'query%3A%28'  # query start
        + 'match%3A%28'  # match start
        + 'geo.dest%3A%28'  # geo.dest start
        + 'query%3AUS%2C'
        + 'type%3Aphrase'
        + '%29'  # geo.dest end
        + '%29'  # match end
        + '%29'  # query end
        + '%29'  # geo.dest filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl


def test_generate_kibana_discover_url_with_filter_and_query_key():
    url = generate_kibana_discover_url(
        rule={
            'kibana_discover_app_url': 'http://kibana:5601/#/discover',
            'kibana_discover_version': '6.8',
            'kibana_discover_index_pattern_id': 'logs-*',
            'timestamp_field': 'timestamp',
            'filter': [
                {'term': {'level': 30}}
            ],
            'query_key': 'status'
        },
        match={
            'timestamp': '2019-09-01T00:30:00Z',
            'status': 'ok'
        }
    )
    expectedUrl = (
        'http://kibana:5601/#/discover'
        + '?_g=%28'  # global start
        + 'refreshInterval%3A%28pause%3A%21t%2Cvalue%3A0%29%2C'
        + 'time%3A%28'  # time start
        + 'from%3A%272019-09-01T00%3A20%3A00Z%27%2C'
        + 'mode%3Aabsolute%2C'
        + 'to%3A%272019-09-01T00%3A40%3A00Z%27'
        + '%29'  # time end
        + '%29'  # global end
        + '&_a=%28'  # app start
        + 'columns%3A%21%28_source%29%2C'
        + 'filters%3A%21%28'  # filters start

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'bool%3A%28must%3A%21%28%28term%3A%28level%3A30%29%29%29%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3Afilter%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Abool%2C'
        + 'negate%3A%21f%2C'
        + 'type%3Acustom%2C'
        + 'value%3A%27%7B%22must%22%3A%5B%7B%22term%22%3A%7B%22level%22%3A30%7D%7D%5D%7D%27'
        + '%29'  # meta end
        + '%29%2C'  # filter end

        + '%28'  # filter start
        + '%27%24state%27%3A%28store%3AappState%29%2C'
        + 'meta%3A%28'  # meta start
        + 'alias%3A%21n%2C'
        + 'disabled%3A%21f%2C'
        + 'index%3A%27logs-%2A%27%2C'
        + 'key%3Astatus%2C'
        + 'negate%3A%21f%2C'
        + 'params%3A%28query%3Aok%2C'  # params start
        + 'type%3Aphrase'
        + '%29%2C'  # params end
        + 'type%3Aphrase%2C'
        + 'value%3Aok'
        + '%29%2C'  # meta end
        + 'query%3A%28'  # query start
        + 'match%3A%28'  # match start
        + 'status%3A%28'  # status start
        + 'query%3Aok%2C'
        + 'type%3Aphrase'
        + '%29'  # status end
        + '%29'  # match end
        + '%29'  # query end
        + '%29'  # filter end

        + '%29%2C'  # filters end
        + 'index%3A%27logs-%2A%27%2C'
        + 'interval%3Aauto'
        + '%29'  # app end
    )
    assert url == expectedUrl
