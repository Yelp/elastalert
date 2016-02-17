# -*- coding: utf-8 -*-
import datetime
import logging

import dateutil.parser
import dateutil.tz

logging.basicConfig()
elastalert_logger = logging.getLogger('elastalert')


def lookup_es_key(lookup_dict, term):
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
    :returns: The value identified by term or None if it cannot be found
    """
    if term in lookup_dict:
        return lookup_dict[term]
    else:
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
        go_deeper = lookup_dict
        subkeys = term.split('.')
        subkey = ''

        while subkeys:
            subkey += subkeys[0]
            subkeys = subkeys[1:]
            if subkey in go_deeper:
                go_deeper = go_deeper[subkey]
                subkey = ''
            else:
                subkey += '.'
        if subkey:
            return None
        return go_deeper


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
    We use the value of some fields from elasticsearch as keys for dictionaries. This means
    that whatever elasticsearch returns must be hashable, and it sometimes returns a list or dict."""
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


def total_seconds(td):
    # For python 2.6 compatability
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def dt_to_int(dt):
    dt = dt.replace(tzinfo=None)
    return int(total_seconds((dt - datetime.datetime.utcfromtimestamp(0))) * 1000)


def unixms_to_dt(ts):
    return unix_to_dt(ts / 1000)


def unix_to_dt(ts):
    dt = datetime.datetime.utcfromtimestamp(ts)
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
