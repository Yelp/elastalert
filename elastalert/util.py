# -*- coding: utf-8 -*-
import datetime
import logging

import dateutil.parser
import dateutil.tz


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
    return ts.replace('000+00:00', 'Z')


def ts_now():
    return datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc()).isoformat()


def inc_ts(timestamp, milliseconds=1):
    """Increment a timestamp by milliseconds."""
    dt = ts_to_dt(timestamp)
    dt += datetime.timedelta(milliseconds=milliseconds)
    return dt_to_ts(dt)


def ts_delta(start, end):
    """Take two timestamps and returns a timedelta object."""
    start_dt = ts_to_dt(start)
    end_dt = ts_to_dt(end)
    return end_dt - start_dt


def pretty_ts(timestamp, tz=True):
    """Pretty-format the given timestamp (to be printed or logged hereafter).
    If tz, the timestamp will be converted to local time.
    Format: MM-DD HH:MM TZ"""
    dt = ts_to_dt(timestamp)
    if tz:
        dt = dt.astimezone(dateutil.tz.tzlocal())
    padding = ''
    if dt.minute < 10:
        padding = '0'
    return '%d-%d %d:%s%d %s' % (dt.month, dt.day,
                                 dt.hour, padding, dt.minute, dt.tzname())


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


def format_index(index, starttime, endtime):
    """ Takes an index, specified using strftime format, start and end time timestamps,
    and outputs a wildcard based index string to match all possible timestamps. """
    start = ts_to_dt(starttime)
    end = ts_to_dt(endtime)

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
