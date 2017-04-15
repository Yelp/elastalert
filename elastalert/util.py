# -*- coding: utf-8 -*-
import os
import datetime
import logging

import dateutil.parser
import dateutil.tz
from auth import Auth
from elasticsearch import RequestsHttpConnection
from elasticsearch.client import Elasticsearch
from six import string_types

logging.basicConfig()
elastalert_logger = logging.getLogger('elastalert')


def new_get_event_ts(ts_field):
    """ Constructs a lambda that may be called to extract the timestamp field
    from a given event.

    :returns: A callable function that takes an event and outputs that event's
    timestamp field.
    """
    return lambda event: lookup_es_key(event[0], ts_field)


def _find_es_dict_by_key(lookup_dict, term):
    """ Performs iterative dictionary search based upon the following conditions:

    1. Subkeys may either appear behind a full stop (.) or at one lookup_dict level lower in the tree.
    2. No wildcards exist within the provided ES search terms (these are treated as string literals)

    This is necessary to get around inconsistencies in ES data.

    For example:
      {'ad.account_name': 'bob'}
    Or:
      {'csp_report': {'blocked_uri': 'bob.com'}}
    And even:
       {'juniper_duo.geoip': {'country_name': 'Democratic People's Republic of Korea'}}

    We want a search term of form "key.subkey.subsubkey" to match in all cases.
    :returns: A tuple with the first element being the dict that contains the key and the second
    element which is the last subkey used to access the target specified by the term. None is
    returned for both if the key can not be found.
    """
    if term in lookup_dict:
        return lookup_dict, term

    # If the term does not match immediately, perform iterative lookup:
    # 1. Split the search term into tokens
    # 2. Recurrently concatenate these together to traverse deeper into the dictionary,
    #    clearing the subkey at every successful lookup.
    #
    # This greedy approach is correct because subkeys must always appear in order,
    # preferring full stops and traversal interchangeably.
    #
    # Subkeys will NEVER be duplicated between an alias and a traversal.
    #
    # For example:
    #  {'foo.bar': {'bar': 'ray'}} to look up foo.bar will return {'bar': 'ray'}, not 'ray'
    dict_cursor = lookup_dict
    subkeys = term.split('.')
    subkey = ''

    while len(subkeys) > 0:
        subkey += subkeys.pop(0)

        if subkey in dict_cursor:
            if len(subkeys) == 0:
                break

            dict_cursor = dict_cursor[subkey]
            subkey = ''
        elif len(subkeys) == 0:
            # If there are no keys left to match, return None values
            dict_cursor = None
            subkey = None
        else:
            subkey += '.'

    return dict_cursor, subkey


def set_es_key(lookup_dict, term, value):
    """ Looks up the location that the term maps to and sets it to the given value.
    :returns: True if the value was set successfully, False otherwise.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)

    if value_dict is not None:
        value_dict[value_key] = value
        return True

    return False


def lookup_es_key(lookup_dict, term):
    """ Performs iterative dictionary search for the given term.
    :returns: The value identified by term or None if it cannot be found.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)
    return None if value_key is None else value_dict[value_key]


def ts_to_dt(timestamp):
    if isinstance(timestamp, datetime.datetime):
        logging.warning('Expected str timestamp, got datetime')
        return timestamp
    dt = dateutil.parser.parse(timestamp)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_ts(dt):
    if not isinstance(dt, datetime.datetime):
        logging.warning('Expected datetime, got %s' % (type(dt)))
        return dt
    ts = dt.isoformat()
    # Round microseconds to milliseconds
    if dt.tzinfo is None:
        # Implicitly convert local times to UTC
        return ts + 'Z'
    # isoformat() uses microsecond accuracy and timezone offsets
    # but we should try to use millisecond accuracy and Z to indicate UTC
    return ts.replace('000+00:00', 'Z').replace('+00:00', 'Z')


def ts_to_dt_with_format(timestamp, ts_format):
    if isinstance(timestamp, datetime.datetime):
        logging.warning('Expected str timestamp, got datetime')
        return timestamp
    dt = datetime.datetime.strptime(timestamp, ts_format)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_ts_with_format(dt, ts_format):
    if not isinstance(dt, datetime.datetime):
        logging.warning('Expected datetime, got %s' % (type(dt)))
        return dt
    ts = dt.strftime(ts_format)
    return ts


def ts_now():
    return datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())


def inc_ts(timestamp, milliseconds=1):
    """Increment a timestamp by milliseconds."""
    dt = ts_to_dt(timestamp)
    dt += datetime.timedelta(milliseconds=milliseconds)
    return dt_to_ts(dt)


def pretty_ts(timestamp, tz=True):
    """Pretty-format the given timestamp (to be printed or logged hereafter).
    If tz, the timestamp will be converted to local time.
    Format: YYYY-MM-DD HH:MM TZ"""
    dt = timestamp
    if not isinstance(timestamp, datetime.datetime):
        dt = ts_to_dt(timestamp)
    if tz:
        dt = dt.astimezone(dateutil.tz.tzlocal())
    return dt.strftime('%Y-%m-%d %H:%M %Z')


def ts_add(ts, td):
    """ Allows a timedelta (td) add operation on a string timestamp (ts) """
    return dt_to_ts(ts_to_dt(ts) + td)


def hashable(obj):
    """ Convert obj to a hashable obj.
    We use the value of some fields from Elasticsearch as keys for dictionaries. This means
    that whatever Elasticsearch returns must be hashable, and it sometimes returns a list or dict."""
    if not obj.__hash__:
        return str(obj)
    return obj


def format_index(index, start, end):
    """ Takes an index, specified using strftime format, start and end time timestamps,
    and outputs a wildcard based index string to match all possible timestamps. """
    # Convert to UTC
    start -= start.utcoffset()
    end -= end.utcoffset()

    indexes = []
    while start.date() <= end.date():
        indexes.append(start.strftime(index))
        start += datetime.timedelta(days=1)

    return ','.join(indexes)


class EAException(Exception):
    pass


def seconds(td):
    return td.seconds + td.days * 24 * 3600


def total_seconds(dt):
    # For python 2.6 compatability
    if dt is None:
        return 0
    elif hasattr(dt, 'total_seconds'):
        return dt.total_seconds()
    else:
        return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10**6) / 10**6


def dt_to_int(dt):
    dt = dt.replace(tzinfo=None)
    return int(total_seconds((dt - datetime.datetime.utcfromtimestamp(0))) * 1000)


def unixms_to_dt(ts):
    return unix_to_dt(float(ts) / 1000)


def unix_to_dt(ts):
    dt = datetime.datetime.utcfromtimestamp(float(ts))
    dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_unix(dt):
    return total_seconds(dt - datetime.datetime(1970, 1, 1, tzinfo=dateutil.tz.tzutc()))


def dt_to_unixms(dt):
    return dt_to_unix(dt) * 1000


def cronite_datetime_to_timestamp(self, d):
    """
    Converts a `datetime` object `d` into a UNIX timestamp.
    """
    if d.tzinfo is not None:
        d = d.replace(tzinfo=None) - d.utcoffset()

    return total_seconds((d - datetime.datetime(1970, 1, 1)))


def add_raw_postfix(field, is_five):
    if is_five:
        end = '.keyword'
    else:
        end = '.raw'
    if not field.endswith(end):
        field += end
    return field


def replace_dots_in_field_names(document):
    """ This method destructively modifies document by replacing any dots in
    field names with an underscore. """
    for key, value in list(document.items()):
        if isinstance(value, dict):
            value = replace_dots_in_field_names(value)
        if isinstance(key, string_types) and key.find('.') != -1:
            del document[key]
            document[key.replace('.', '_')] = value
    return document


def elasticsearch_client(conf):
    """ returns an Elasticsearch instance configured using an es_conn_config """
    es_conn_conf = build_es_conn_config(conf)
    auth = Auth()
    es_conn_conf['http_auth'] = auth(host=es_conn_conf['es_host'],
                                     username=es_conn_conf['es_username'],
                                     password=es_conn_conf['es_password'],
                                     aws_region=es_conn_conf['aws_region'],
                                     profile_name=es_conn_conf['profile'])

    return Elasticsearch(host=es_conn_conf['es_host'],
                         port=es_conn_conf['es_port'],
                         url_prefix=es_conn_conf['es_url_prefix'],
                         use_ssl=es_conn_conf['use_ssl'],
                         verify_certs=es_conn_conf['verify_certs'],
                         connection_class=RequestsHttpConnection,
                         http_auth=es_conn_conf['http_auth'],
                         timeout=es_conn_conf['es_conn_timeout'],
                         send_get_body_as=es_conn_conf['send_get_body_as'])


def build_es_conn_config(conf):
    """ Given a conf dictionary w/ raw config properties 'use_ssl', 'es_host', 'es_port'
    'es_username' and 'es_password', this will return a new dictionary
    with properly initialized values for 'es_host', 'es_port', 'use_ssl' and 'http_auth' which
    will be a basicauth username:password formatted string """
    parsed_conf = {}
    parsed_conf['use_ssl'] = os.environ.get('ES_USE_SSL', False)
    parsed_conf['verify_certs'] = True
    parsed_conf['http_auth'] = None
    parsed_conf['es_username'] = None
    parsed_conf['es_password'] = None
    parsed_conf['aws_region'] = None
    parsed_conf['profile'] = None
    parsed_conf['es_host'] = os.environ.get('ES_HOST', conf['es_host'])
    parsed_conf['es_port'] = int(os.environ.get('ES_PORT', conf['es_port']))
    parsed_conf['es_url_prefix'] = ''
    parsed_conf['es_conn_timeout'] = conf.get('es_conn_timeout', 20)
    parsed_conf['send_get_body_as'] = conf.get('es_send_get_body_as', 'GET')

    if 'es_username' in conf:
        parsed_conf['es_username'] = os.environ.get('ES_USERNAME', conf['es_username'])
        parsed_conf['es_password'] = os.environ.get('ES_PASSWORD', conf['es_password'])

    if 'aws_region' in conf:
        parsed_conf['aws_region'] = conf['aws_region']

    # Deprecated
    if 'boto_profile' in conf:
        logging.warning('Found deprecated "boto_profile", use "profile" instead!')
        parsed_conf['profile'] = conf['boto_profile']

    if 'profile' in conf:
        parsed_conf['profile'] = conf['profile']

    if 'use_ssl' in conf:
        parsed_conf['use_ssl'] = conf['use_ssl']

    if 'verify_certs' in conf:
        parsed_conf['verify_certs'] = conf['verify_certs']

    if 'es_url_prefix' in conf:
        parsed_conf['es_url_prefix'] = conf['es_url_prefix']

    return parsed_conf
