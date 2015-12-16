import datetime
import urllib

from util import ts_to_dt, dt_to_ts

kibana4_uri_fmt = """_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:'{q_start}',mode:absolute,to:'{q_end}'))&_a=(columns:!({columns}),filters:!(),index:'logstash-*',interval:auto,query:(query_string:(analyze_wildcard:!t,query:'{query}')),sort:!('{sort_field}',{order}))"""
def kibana4_context_args(match, context_time=30, query=None,
                         sort_field='timestamp_micros', order='asc',
                         columns="host,program,message"):

    if not query:
        query = 'host:"%s"AND program:"%s"' % (match['host'], match['program'])

    query = urllib.quote(query)
    match_dt = ts_to_dt(match['@timestamp'])

    context_timedelta = datetime.timedelta(seconds=context_time)
    q_start = dt_to_ts(match_dt - context_timedelta)
    q_end   = dt_to_ts(match_dt + context_timedelta)

    r = kibana4_uri_fmt.format(q_start=q_start, q_end=q_end, columns=columns, query=query, sort_field=sort_field,order=order)

    return r
