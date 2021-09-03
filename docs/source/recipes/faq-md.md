My rule is not getting any hits?
==========

So you've managed to set up ElastAlert 2, write a rule, and run it, but nothing happens, or it says
``0 query hits``. First of all, we recommend using the command ``elastalert-test-rule rule.yaml`` to
debug. It will show you how many documents match your filters for the last 24 hours (or more, see
``--help``), and then shows you if any alerts would have fired. If you have a filter in your rule,
remove it and try again. This will show you if the index is correct and that you have at least some
documents. If you have a filter in Kibana and want to recreate it in ElastAlert 2, you probably want
to use a query string. Your filter will look like

```
filter:
- query:
    query_string:
      query: "foo: bar AND baz: abc*"
```
If you receive an error that Elasticsearch is unable to parse it, it's likely the YAML is not spaced
correctly, and the filter is not in the right format. If you are using other types of filters, like
``term``, a common pitfall is not realizing that you may need to use the analyzed token. This is the
default if you are using Logstash. For example,

```
filter:
- term:
    foo: "Test Document"
```

will not match even if the original value for ``foo`` was exactly "Test Document". Instead, you want
to use ``foo.raw``. If you are still having trouble troubleshooting why your documents do not match,
try running ElastAlert 2 with ``--es_debug_trace /path/to/file.log``. This will log the queries made
to Elasticsearch in full so that you can see exactly what is happening.

I got hits, why didn't I get an alert?
==========

If you got logs that had ``X query hits, 0 matches, 0 alerts sent``, it depends on the ``type`` why
you didn't get any alerts. If ``type: any``, a match will occur for every hit. If you are using
``type: frequency``, ``num_events`` must occur within ``timeframe`` of each other for a match to
occur. Different rules apply for different rule types.

If you see ``X matches, 0 alerts sent``, this may occur for several reasons. If you set
``aggregation``, the alert will not be sent until after that time has elapsed. If you have gotten an
alert for this same rule before, that rule may be silenced for a period of time. The default is one
minute between alerts. If a rule is silenced, you will see ``Ignoring match for silenced rule`` in
the logs.

If you see ``X alerts sent`` but didn't get any alert, it's probably related to the alert
configuration. If you are using the ``--debug`` flag, you will not receive any alerts. Instead, the
alert text will be written to the console. Use ``--verbose`` to achieve the same affects without
preventing alerts. If you are using email alert, make sure you have it configured for an SMTP
server. By default, it will connect to localhost on port 25. It will also use the word "elastalert"
as the "From:" address. Some SMTP servers will reject this because it does not have a domain while
others will add their own domain automatically. See the email section in the documentation for how
to configure this.

Why did I only get one alert when I expected to get several?
==========

There is a setting called ``realert`` which is the minimum time between two alerts for the same
rule. Any alert that occurs within this time will simply be dropped. The default value for this is
one minute. If you want to receive an alert for every single match, even if they occur right after
each other, use

```
realert:
  minutes: 0
```

You can of course set it higher as well.

How can I prevent duplicate alerts?
==========

By setting ``realert``, you will prevent the same rule from alerting twice in an amount of time.

```
realert:
  days: 1
```

You can also prevent duplicates based on a certain field by using ``query_key``. For example, to
prevent multiple alerts for the same user, you might use

```
realert:
  hours: 8
query_key: user
```

Note that this will also affect the way many rule types work. If you are using ``type: frequency``
for example, ``num_events`` for a single value of ``query_key`` must occur before an alert will be
sent. You can also use a compound of multiple fields for this key. For example, if you only wanted
to receieve an alert once for a specific error and hostname, you could use

```
query_key: [error, hostname]
```

You can also write in the following way.

```
query_key:
  - error
  - hostname
```

Internally, this works by creating a new field for each document called ``field1,field2`` with a
value of ``value1,value2`` and using that as the ``query_key``.

The data for when an alert will fire again is stored in Elasticsearch in the ``elastalert_status``
index, with a ``_type`` of ``silence`` and also cached in memory.

How can I change what's in the alert?
==========

You can use the field ``alert_text`` to add custom text to an alert. By setting ``alert_text_type:
alert_text_only`` Or ``alert_text_type: alert_text_jinja``, it will be the entirety of the alert.
You can also add different fields from the alert:

With ``alert_text_type: alert_text_jinja`` by using [Jinja2](https://pypi.org/project/Jinja2/)
Template.

```
alert_text_type: alert_text_jinja

alert_text: |
  Alert triggered! *({{num_hits}} Matches!)*
  Something happened with {{username}} ({{email}})
  {{description|truncate}}

```

- Top fields are accessible via `{{field_name}}` or `{{_data['field_name']}}`, `_data` is useful
  when accessing *fields with dots in their keys*, as Jinja treat dot as a nested field.
- If `_data` conflicts with your top level data, use  ``jinja_root_name`` to change its name.

With ``alert_text_type: alert_text_only`` by using Python style string formatting and
``alert_text_args``. For example

```
alert_text: "Something happened with {0} at {1}"
alert_text_type: alert_text_only
alert_text_args: ["username", "@timestamp"]
```

You can also limit the alert to only containing certain fields from the document by using
``include``.

```
include: ["ip_address", "hostname", "status"]
```

My alert only contains data for one event, how can I see more?
==========

If you are using ``type: frequency``, you can set the option ``attach_related: true`` and every
document will be included in the alert. An alternative, which works for every type, is
``top_count_keys``. This will show the top counts for each value for certain fields. For example, if
you have

```
top_count_keys: ["ip_address", "status"]
```

and 10 documents matched your alert, it may contain something like

```
ip_address:
127.0.0.1: 7
10.0.0.1: 2
192.168.0.1: 1

status:
200: 9
500: 1
```

How can I make the alert come at a certain time?
==========

The ``aggregation`` feature will take every alert that has occured over a period of time and send
them together in one alert. You can use cron style syntax to send all alerts that have occured since
the last once by using

```
aggregation:
  schedule: '2 4 * * mon,fri'
```

I have lots of documents and it's really slow, how can I speed it up?
==========

There are several ways to potentially speed up queries. If you are using ``index: logstash-*``,
Elasticsearch will query all shards, even if they do not possibly contain data with the correct
timestamp. Instead, you can use Python time format strings and set ``use_strftime_index``

```
index: logstash-%Y.%m
use_strftime_index: true
```

Another thing you could change is ``buffer_time``. By default, ElastAlert 2 will query large
overlapping windows in order to ensure that it does not miss any events, even if they are indexed in
real time. In config.yaml, you can adjust ``buffer_time`` to a smaller number to only query the most
recent few minutes.

```
buffer_time:
  minutes: 5
```

By default, ElastAlert 2 will download every document in full before processing them. Instead, you can
have ElastAlert 2 simply get a count of the number of documents that have occured in between each
query. To do this, set ``use_count_query: true``. This cannot be used if you use ``query_key``,
because ElastAlert 2 will not know the contents of each documents, just the total number of them. This
also reduces the precision of alerts, because all events that occur between each query will be
rounded to a single timestamp.

If you are using ``query_key`` (a single key, not multiple keys) you can use ``use_terms_query``.
This will make ElastAlert 2 perform a terms aggregation to get the counts for each value of a certain
field. Both ``use_terms_query`` and ``use_count_query`` also require ``doc_type`` to be set to the
``_type`` of the documents. They may not be compatible with all rule types.

Can I perform aggregations?
==========

The only aggregation supported currently is a terms aggregation, by setting ``use_terms_query``.

I'm not using @timestamp, what do I do?
==========

You can use ``timestamp_field`` to change which field ElastAlert 2 will use as the timestamp. You can
use ``timestamp_type`` to change it between ISO 8601 and unix timestamps. You must have some kind of
timestamp for ElastAlert 2 to work. If your events are not in real time, you can use ``query_delay``
and ``buffer_time`` to adjust when ElastAlert 2 will look for documents.

I'm using flatline but I don't see any alerts
==========

When using ``type: flatline``, ElastAlert 2 must see at least one document before it will alert you
that it has stopped seeing them.

How can I get a "resolve" event?
==========

ElastAlert 2 does not currently support stateful alerts or resolve events. However, if you have a rule
alerting you that a condition has occurred, such as a service being down, then you can create a
second rule that will monitor the first rule, and alert you when the first rule ceases to trigger.

For example, assuming you already have a rule named "Service is offline" that's working today, you 
can add a second rule as follows:

```
name: Service is back online
type: flatline
index: elastalert*
query_key: "rule_name"
filter:
- query:
    query_string:
      query: "rule_name:\"Service is offline\" AND matches:>0"
forget_keys: true
timeframe:
  minutes: 30
threshold: 1
```

This second rule will trigger after the timeframe of 30 minutes has elapsed with no further matches
against the first rule.

Can I set a warning threshold?
==========

Currently, the only way to set a warning threshold is by creating a second rule with a lower
threshold.

Does it support Elastic Cloud's "Cloud ID"?
==========

Not supported.

In addition, there is a reason why we cannot handle it at present.
ElastAlert 2 uses elasticsearch-py 7.0.0, because Elastic Cloud cloud_id support is from elasticsearch-py 7.0.2. 

I need to go through an http (s) proxy to connect to Elasticsearch. Does ElastAlert 2 support it?
==========

Not supported.

About boolean value
==========

You can use all lowercase letters or only uppercase letters at the beginning.

example

```
# OK
use_ssl: true
# OK
use_ssl: True
# OK
use_ssl: false
# OK
use_ssl: False
```

Is it possible to send an SNMP Trap with an alert notification?
==========

* You need to additionally install snmp snmptrapd on the docker image. In other words, you need to modify the Dockerfile and recreate the Docker image with docker build.
* It is possible with the command Alerter.

example

```
name: "mariadb-error-log-warning"
type: "frequency"
index: "mariadb-*"
num_events: 1
timeframe:
    minutes: 5
realert:
  minutes: 1
filter:
  - query:
      query_string:
        query: "@log_name:mysqld.error AND message:Warning"
alert:
  - command
command: ["/usr/bin/snmptrap", "-IR", "-v", "2c", "-c", "public", "xxx.xxx.xxx.xxxxx:xxx", "", "netSnmp.99999", "netSnmp.99999.1", "s", "Hello, World"]
is_enabled: true
timestamp_field: "@timestamp"
timestamp_type: "iso"
use_strftime_index: false
```

Is Email Alerter compatible with Microsoft 365 (formerly Office 365)?
==========

Not supported.

Does Email Alerter support the Google Gmail API?
==========

Not supported.

Can Email Alerter send emails via the Gmail sending server?
==========

It is possible. However, you need to turn on (enable) the item "Access to insecure apps" in the "Security" settings of your Google account.

Is it possible to send a JPEG image encoded as base64 in elasticsearch as an image attachment with an Email Alerter?
==========

Yes, this is possible if the base64 encoded bytes are available in the matched document, as shown in the example below:

```
include: [base64field]
alert_text_args: [base64field]
email_format: "html"
alert_text_type: alert_text_only
alert_text: |
  <html>
  <body>
  <div>
    <img src="data:image/jpg;base64, {}" alt="Image" />
  </div>
  </body>
  </html>
```

Does the alert notification destination support Alertmanager?
==========

Not supported.

The es_host parameter seems to use only one host. Is it possible to specify multiple nodes?
==========

Only one can be set in es_host.
Please use haproxy in front of elasticsearch to support multiple hosts.

Is there any plan to implement a REST API into this project?
==========

No plan.

An error occurred when trying to create a blacklist rule that parses a file with more than 1024 lines.
==========

This is the default limit for ElasticSearch. Specifying more than 1024 items in the blacklist will result in an error.
This is a known issue. Perhaps White List can have similar issues.
See the following issues on the original yelp/elastalert for more information.

https://github.com/Yelp/elastalert/issues/1867<br>
https://github.com/Yelp/elastalert/issues/2704
