Rule Types and Configuration Options
************************************

Examples of several types of rule configuration can be found in the ``examples/rules`` folder.

.. _commonconfig:

.. note:: All "time" formats are of the form ``unit: X`` where unit is one of weeks, days, hours, minutes or seconds.
    Such as ``minutes: 15`` or ``hours: 1``.


Rule Configuration Cheat Sheet
==============================


+--------------------------------------------------------------------------+
|              FOR ALL RULES                                               |
+==============================================================+===========+
| ``es_host`` (string)                                         |  Required |
+--------------------------------------------------------------+           |
| ``es_port`` (number)                                         |           |
+--------------------------------------------------------------+           |
| ``index`` (string)                                           |           |
+--------------------------------------------------------------+           |
| ``type`` (string)                                            |           |
+--------------------------------------------------------------+           |
| ``alert`` (string or list)                                   |           |
+--------------------------------------------------------------+-----------+
| ``es_hosts`` (list, no default)                              |           |
+--------------------------------------------------------------+           |
| ``name`` (string, defaults to the filename)                  |           |
+--------------------------------------------------------------+           |
| ``use_strftime_index`` (boolean, default False)              |  Optional |
+--------------------------------------------------------------+           |
| ``use_ssl`` (boolean, default False)                         |           |
+--------------------------------------------------------------+           |
| ``verify_certs`` (boolean, default True)                     |           |
+--------------------------------------------------------------+           |
| ``ssl_show_warn`` (boolean, default True)                    |           |
+--------------------------------------------------------------+           |
| ``es_username`` (string, no default)                         |           |
+--------------------------------------------------------------+           |
| ``es_password`` (string, no default)                         |           |
+--------------------------------------------------------------+           |
| ``es_bearer`` (string, no default)                           |           |
+--------------------------------------------------------------+           |
| ``es_api_key`` (string, no default)                          |           |
+--------------------------------------------------------------+           |
| ``es_url_prefix`` (string, no default)                       |           |
+--------------------------------------------------------------+           |
| ``statsd_instance_tag`` (string, no default)                 |           |
+--------------------------------------------------------------+           |
| ``statsd_host`` (string, no default)                         |           |
+--------------------------------------------------------------+           |
| ``es_send_get_body_as`` (string, default "GET")              |           |
+--------------------------------------------------------------+           |
| ``aggregation`` (time, no default)                           |           |
+--------------------------------------------------------------+           |
| ``limit_execution`` (string, no default)                     |           |
+--------------------------------------------------------------+           |
| ``description`` (string, default empty string)               |           |
+--------------------------------------------------------------+           |
| ``generate_kibana_link`` (boolean, default False)            |           |
+--------------------------------------------------------------+           |
| ``use_kibana_dashboard`` (string, no default)                |           |
+--------------------------------------------------------------+           |
| ``kibana_url`` (string, default from es_host)                |           |
+--------------------------------------------------------------+           |
| ``kibana_username`` (string, no default)                     |           |
+--------------------------------------------------------------+           |
| ``kibana_password`` (string, no default)                     |           |
+--------------------------------------------------------------+           |
| ``use_kibana4_dashboard`` (string, no default)               |           |
+--------------------------------------------------------------+           |
| ``kibana4_start_timedelta`` (time, default: 10 min)          |           |
+--------------------------------------------------------------+           |
| ``kibana4_end_timedelta`` (time, default: 10 min)            |           |
+--------------------------------------------------------------+           |
| ``generate_kibana_discover_url`` (boolean, default False)    |           |
+--------------------------------------------------------------+           |
| ``shorten_kibana_discover_url`` (boolean, default False)     |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_app_url`` (string, no default)             |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_version`` (string, no default)             |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_index_pattern_id`` (string, no default)    |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_security_tenant``  (string, no default)    |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_columns`` (list of strs, default _source)  |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_from_timedelta`` (time, default: 10 min)   |           |
+--------------------------------------------------------------+           |
| ``kibana_discover_to_timedelta`` (time, default: 10 min)     |           |
+--------------------------------------------------------------+           |
| ``use_local_time`` (boolean, default True)                   |           |
+--------------------------------------------------------------+           |
| ``realert`` (time, default: 1 min)                           |           |
+--------------------------------------------------------------+           |
| ``exponential_realert`` (time, no default)                   |           |
+--------------------------------------------------------------+           |
| ``match_enhancements`` (list of strs, no default)            |           |
+--------------------------------------------------------------+           |
| ``top_count_number`` (int, default 5)                        |           |
+--------------------------------------------------------------+           |
| ``top_count_keys`` (list of strs)                            |           |
+--------------------------------------------------------------+           |
| ``raw_count_keys`` (boolean, default True)                   |           |
+--------------------------------------------------------------+           |
| ``include`` (list of strs, default ["*"])                    |           |
+--------------------------------------------------------------+           |
| ``filter`` (ES filter DSL, no default)                       |           |
+--------------------------------------------------------------+           |
| ``max_query_size`` (int, default global max_query_size)      |           |
+--------------------------------------------------------------+           |
| ``query_delay`` (time, default 0 min)                        |           |
+--------------------------------------------------------------+           |
| ``owner`` (string, default empty string)                     |           |
+--------------------------------------------------------------+           |
| ``priority`` (int, default 2)                                |           |
+--------------------------------------------------------------+           |
| ``category`` (string, default empty string)                  |           |
+--------------------------------------------------------------+           |
| ``scan_entire_timeframe`` (bool, default False)              |           |
+--------------------------------------------------------------+           |
| ``query_timezone`` (string, default empty string)            |           |
+--------------------------------------------------------------+           |
| ``import`` (string)                                          |           |
|                                                              |           |
| IGNORED IF ``use_count_query`` or ``use_terms_query`` is true|           |
+--------------------------------------------------------------+           +
| ``buffer_time`` (time, default from config.yaml)             |           |
+--------------------------------------------------------------+           |
| ``timestamp_type`` (string, default iso)                     |           |
+--------------------------------------------------------------+           |
| ``timestamp_format`` (string, default "%Y-%m-%dT%H:%M:%SZ")  |           |
+--------------------------------------------------------------+           |
| ``timestamp_format_expr`` (string, no default )              |           |
+--------------------------------------------------------------+           |
| ``_source_enabled`` (boolean, default True)                  |           |
+--------------------------------------------------------------+           |
| ``alert_text_args`` (array of strs)                          |           |
+--------------------------------------------------------------+           |
| ``alert_text_kw`` (object)                                   |           |
+--------------------------------------------------------------+           |
| ``alert_missing_value`` (string, default "<MISSING VALUE>")  |           |
+--------------------------------------------------------------+           |
| ``is_enabled`` (boolean, default True)                       |           |
+--------------------------------------------------------------+-----------+
| ``search_extra_index`` (boolean, default False)              |           |
+--------------------------------------------------------------+-----------+

|

+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|      RULE TYPE                                     |   Any  | Blacklist | Whitelist | Change | Frequency | Spike | Flatline |New_term|Cardinality|
+====================================================+========+===========+===========+========+===========+=======+==========+========+===========+
| ``compare_key`` (list of strs, no default)         |        |    Req    |   Req     |  Req   |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``blacklist`` (list of strs, no default)            |        |    Req    |           |        |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``whitelist`` (list of strs, no default)            |        |           |   Req     |        |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``ignore_null`` (boolean, no default)              |        |           |   Req     |  Req   |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``query_key`` (string or list, no default)         |   Opt  |           |           |   Req  |    Opt    |  Opt  |   Opt    |  Req   |  Opt      |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``aggregation_key`` (string, no default)           |   Opt  |           |           |        |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``summary_table_fields`` (list, no default)        |   Opt  |           |           |        |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``timeframe`` (time, no default)                   |        |           |           |   Opt  |    Req    |  Req  |   Req    |        |  Req      |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``num_events`` (int, no default)                   |        |           |           |        |    Req    |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``attach_related`` (boolean, no default)           |        |           |           |        |    Opt    |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``use_count_query`` (boolean, no default)           |        |           |           |        |     Opt   | Opt   | Opt      |        |           |
|                                                    |        |           |           |        |           |       |          |        |           |
|``doc_type`` (string, no default)                   |        |           |           |        |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``use_terms_query`` (boolean, no default)           |        |           |           |        |     Opt   | Opt   |          | Opt    |           |
|                                                    |        |           |           |        |           |       |          |        |           |
|``doc_type`` (string, no default)                   |        |           |           |        |           |       |          |        |           |
|                                                    |        |           |           |        |           |       |          |        |           |
|``query_key`` (string or list, no default)          |        |           |           |        |           |       |          |        |           |
|                                                    |        |           |           |        |           |       |          |        |           |
|``terms_size`` (int, default 50)                    |        |           |           |        |           |       |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``spike_height`` (int, no default)                 |        |           |           |        |           |   Req |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``spike_type`` ([up|down|both], no default)         |        |           |           |        |           |   Req |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``alert_on_new_data`` (boolean, default False)      |        |           |           |        |           |   Opt |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``threshold_ref`` (int, no default)                 |        |           |           |        |           |   Opt |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``threshold_cur`` (int, no default)                 |        |           |           |        |           |   Opt |          |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``threshold`` (int, no default)                     |        |           |           |        |           |       |    Req   |        |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``fields`` (string or list, no default)             |        |           |           |        |           |       |          | Req    |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``terms_window_size`` (time, default 30 days)       |        |           |           |        |           |       |          | Opt    |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``window_step_size`` (time, default 1 day)          |        |           |           |        |           |       |          | Opt    |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``alert_on_missing_fields`` (boolean, default False)|        |           |           |        |           |       |          | Opt    |           |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``cardinality_field`` (string, no default)          |        |           |           |        |           |       |          |        |  Req      |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``max_cardinality`` (boolean, no default)           |        |           |           |        |           |       |          |        |  Opt      |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``min_cardinality`` (boolean, no default)           |        |           |           |        |           |       |          |        |  Opt      |
+----------------------------------------------------+--------+-----------+-----------+--------+-----------+-------+----------+--------+-----------+

Common Configuration Options
============================

Every file that ends in ``.yaml`` in the ``rules_folder`` will be run by default.
The following configuration settings are common to all types of rules.

Required Settings
~~~~~~~~~~~~~~~~~

es_host
^^^^^^^

``es_host``: The hostname of the Elasticsearch cluster the rule will use to query. (Required, string, no default)
The environment variable ``ES_HOST`` will override this field.
For multiple host Elasticsearch clusters see ``es_hosts`` parameter.

es_port
^^^^^^^

``es_port``: The port of the Elasticsearch cluster. (Required, number, no default)
The environment variable ``ES_PORT`` will override this field.

index
^^^^^

``index``: The name of the index that will be searched. Wildcards can be used here, such as:
``index: my-index-*`` which will match ``my-index-2014-10-05``. You can also use a format string containing
``%Y`` for year, ``%m`` for month, and ``%d`` for day. To use this, you must also set ``use_strftime_index`` to true. (Required, string, no default)

name
^^^^

``name``: The name of the rule. This must be unique across all rules. The name will be used in
alerts and used as a key when writing and reading search metadata back from Elasticsearch. (Required, string, no default)

type
^^^^

``type``: The ``RuleType`` to use. This may either be one of the built in rule types, see :ref:`Rule Types <ruletypes>` section below for more information,
or loaded from a module. For loading from a module, the type should be specified as ``module.file.RuleName``. (Required, string, no default)

alert
^^^^^

``alert``: The ``Alerter`` type to use. This may be one or more of the built in alerts, see :ref:`Alert Types <alerts>` section below for more information,
or loaded from a module. For loading from a module, the alert should be specified as ``module.file.AlertName``. (Required, string or list, no default)

Optional Settings
~~~~~~~~~~~~~~~~~
es_hosts
^^^^^^^^

``es_hosts``: The list of nodes of the Elasticsearch cluster that the rule will use for the request. (Optional, list, default none). Values can be specified as ``host:port`` if overriding the default port.
The environment variable ``ES_HOSTS`` will override this field, and can be specified as a comma-separated value. Note that the ``es_host`` parameter must still be specified in order to identify a primary Elasticsearch host. 

import
^^^^^^

``import``: If specified includes all the settings from this yaml file. This allows common config options to be shared. Note that imported files that aren't
complete rules should not have a ``.yml`` or ``.yaml`` suffix so that ElastAlert 2 doesn't treat them as rules. Filters in imported files are merged (ANDed)
with any filters in the rule. You can only have one import per rule, though the imported file can import another file or multiple files, recursively.
The filename can be an absolute path or relative to the rules directory. (Optional, string or array of strings, no default)

use_ssl
^^^^^^^

``use_ssl``: Whether or not to connect to ``es_host`` using TLS. (Optional, boolean, default False)
The environment variable ``ES_USE_SSL`` will override this field.

ssl_show_warn
^^^^^^^^^^^^^

``ssl_show_warn``: Whether or not to show SSL/TLS warnings when ``verify_certs`` is disabled. (Optional, boolean, default True)

verify_certs
^^^^^^^^^^^^

``verify_certs``: Whether or not to verify TLS certificates. (Optional, boolean, default True)

client_cert
^^^^^^^^^^^

``client_cert``: Path to a PEM certificate to use as the client certificate (Optional, string, no default)

client_key
^^^^^^^^^^^

``client_key``: Path to a private key file to use as the client key (Optional, string, no default)

ca_certs
^^^^^^^^

``ca_certs``: Path to a CA cert bundle to use to verify SSL connections (Optional, string, no default)

es_username
^^^^^^^^^^^

``es_username``: basic-auth username for connecting to ``es_host``. (Optional, string, no default) The environment variable ``ES_USERNAME`` will override this field.

es_password
^^^^^^^^^^^

``es_password``: basic-auth password for connecting to ``es_host``. (Optional, string, no default) The environment variable ``ES_PASSWORD`` will override this field.

es_bearer
^^^^^^^^^^^

``es_bearer``: bearer-token authorization for connecting to ``es_host``. (Optional, string, no default) The environment variable ``ES_BEARER`` will override this field. This authentication option will override the password authentication option.

es_api_key
^^^^^^^^^^^

``es_api_key``: api-key-token authorization for connecting to ``es_host``. (Optional, base64 string, no default) The environment variable ``ES_API_KEY`` will override this field. This authentication option will override both the bearer and the password authentication options.

es_url_prefix
^^^^^^^^^^^^^

``es_url_prefix``: URL prefix for the Elasticsearch endpoint. (Optional, string, no default)

statsd_instance_tag
^^^^^^^^^^^^^^^^^^^

``statsd_instance_tag``: prefix for statsd metrics. (Optional, string, no default)


statsd_host
^^^^^^^^^^^^^

``statsd_host``: statsd host. (Optional, string, no default)

es_send_get_body_as
^^^^^^^^^^^^^^^^^^^

``es_send_get_body_as``: Method for querying Elasticsearch. (Optional, string, default "GET")

use_strftime_index
^^^^^^^^^^^^^^^^^^

``use_strftime_index``: If this is true, ElastAlert 2 will format the index using datetime.strftime for each query.
See https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior for more details.
If a query spans multiple days, the formatted indexes will be concatenated with commas. This is useful
as narrowing the number of indexes searched, compared to using a wildcard, may be significantly faster. For example, if ``index`` is
``logstash-%Y.%m.%d``, the query url will be similar to ``elasticsearch.example.com/logstash-2015.02.03/...`` or
``elasticsearch.example.com/logstash-2015.02.03,logstash-2015.02.04/...``.

search_extra_index
^^^^^^^^^^^^^^^^^^

``search_extra_index``: If this is true, ElastAlert 2 will add an extra index on the early side onto each search. For example, if it's querying
completely within 2018-06-28, it will actually use 2018-06-27,2018-06-28. This can be useful if your timestamp_field is not what's being used
to generate the index names. If that's the case, sometimes a query would not have been using the right index.

aggregation
^^^^^^^^^^^

``aggregation``: This option allows you to aggregate multiple matches together into one alert. Every time a match is found,
ElastAlert 2 will wait for the ``aggregation`` period, and send all of the matches that have occurred in that time for a particular
rule together.

For example::

    aggregation:
      hours: 2

means that if one match occurred at 12:00, another at 1:00, and a third at 2:30, one
alert would be sent at 2:00, containing the first two matches, and another at 4:30, containing the third match plus any additional matches
occurring before 4:30. This can be very useful if you expect a large number of matches and only want a periodic report. (Optional, time, default none)

If you wish to aggregate all your alerts and send them on a recurring interval, you can do that using the ``schedule`` field.

For example, if you wish to receive alerts every Monday and Friday::

    aggregation:
      schedule: '2 4 * * mon,fri'

This uses Cron syntax, which you can read more about `here <http://www.nncron.ru/help/EN/working/cron-format.htm>`_. Make sure to `only` include either a schedule field or standard datetime fields (such as ``hours``, ``minutes``, ``days``), not both.

By default, all events that occur during an aggregation window are grouped together. However, if your rule has the ``aggregation_key`` field set, then each event sharing a common key value will be grouped together. A separate aggregation window will be made for each newly encountered key value.

For example, if you wish to receive alerts that are grouped by the user who triggered the event, you can set::

    aggregation_key: 'my_data.username'

Then, assuming an aggregation window of 10 minutes, if you receive the following data points::

    {'my_data': {'username': 'alice', 'event_type': 'login'}, '@timestamp': '2016-09-20T00:00:00'}
    {'my_data': {'username': 'bob', 'event_type': 'something'}, '@timestamp': '2016-09-20T00:05:00'}
    {'my_data': {'username': 'alice', 'event_type': 'something else'}, '@timestamp': '2016-09-20T00:06:00'}

This should result in 2 alerts: One containing alice's two events, sent at ``2016-09-20T00:10:00`` and one containing bob's one event sent at ``2016-09-20T00:16:00``

For aggregations, there can sometimes be a large number of documents present in the viewing medium (email, Jira ticket, etc..). If you set the ``summary_table_fields`` field, ElastAlert 2 will provide a summary of the specified fields from all the results.

The formatting style of the summary table can be switched between ``ascii`` (default) and ``markdown`` with parameter ``summary_table_type``. ``markdown`` might be the more suitable formatting for alerters supporting it like TheHive.

The maximum number of rows in the summary table can be limited with the parameter ``summary_table_max_rows``.

For example, if you wish to summarize the usernames and event_types that appear in the documents so that you can see the most relevant fields at a quick glance, you can set::

    summary_table_fields:
        - my_data.username
        - my_data.event_type

Then, for the same sample data shown above listing alice and bob's events, ElastAlert 2 will provide the following summary table in the alert medium::

    +------------------+--------------------+
    | my_data.username | my_data.event_type |
    +------------------+--------------------+
    |      alice       |       login        |
    |       bob        |     something      |
    |      alice       |   something else   |
    +------------------+--------------------+


.. note::
   By default, aggregation time is relative to the current system time, not the time of the match. This means that running ElastAlert 2 over
   past events will result in different alerts than if ElastAlert 2 had been running while those events occured. This behavior can be changed
   by setting ``aggregate_by_match_time``.

limit_execution
^^^^^^^^^^^^^^^

``limit_execution``: This option allows you to activate the rule during a limited period of time. This uses the cron format.

For example, if you wish to activate the rule from monday to friday, between 10am to 6pm::

    limit_execution: "* 10-18 * * 1-5"

aggregate_by_match_time
^^^^^^^^^^^^^^^^^^^^^^^

Setting this to true will cause aggregations to be created relative to the timestamp of the first event, rather than the current time. This
is useful for querying over historic data or if using a very large buffer_time and you want multiple aggregations to occur from a single query.

realert
^^^^^^^

``realert``: This option allows you to ignore repeating alerts for a period of time. If the rule uses a ``query_key``, this option
will be applied on a per key basis. All matches for a given rule, or for matches with the same ``query_key``, will be ignored for
the given time. All matches with a missing ``query_key`` will be grouped together using a value of ``_missing``.
This is applied to the time the alert is sent, not to the time of the event. It defaults to one minute, which means
that if ElastAlert 2 is run over a large time period which triggers many matches, only the first alert will be sent by default. If you want
every alert, set realert to 0 minutes. (Optional, time, default 1 minute)

exponential_realert
^^^^^^^^^^^^^^^^^^^

``exponential_realert``: This option causes the value of ``realert`` to exponentially increase while alerts continue to fire. If set,
the value of ``exponential_realert`` is the maximum ``realert`` will increase to. If the time between alerts is less than twice ``realert``,
``realert`` will double. For example, if ``realert: minutes: 10`` and ``exponential_realert: hours: 1``, an alerts fires at 1:00 and another
at 1:15, the next alert will not be until at least 1:35. If another alert fires between 1:35 and 2:15, ``realert`` will increase to the
1 hour maximum. If more than 2 hours elapse before the next alert, ``realert`` will go back down. Note that alerts that are ignored (e.g.
one that occurred at 1:05) would not change ``realert``. (Optional, time, no default)

buffer_time
^^^^^^^^^^^

``buffer_time``: This options allows the rule to override the ``buffer_time`` global setting defined in config.yaml. This value is ignored if
``use_count_query`` or ``use_terms_query`` is true. (Optional, time)

query_delay
^^^^^^^^^^^

``query_delay``: This option will cause ElastAlert 2 to subtract a time delta from every query, causing the rule to run with a delay.
This is useful if the data is Elasticsearch doesn't get indexed immediately. (Optional, time)

For example::

    query_delay:
      hours: 2

owner
^^^^^

``owner``: This value will be used to identify the stakeholder of the alert. Optionally, this field can be included in any alert type. (Optional, string)

priority
^^^^^^^^

``priority``: This value will be used to identify the relative priority of the alert. Optionally, this field can be included in any alert type (e.g. for use in email subject/body text). (Optional, int, default 2)

category
^^^^^^^^

``category``: This value will be used to identify the category of the alert. Optionally, this field can be included in any alert type (e.g. for use in email subject/body text). (Optional, string, default empty string)

max_query_size
^^^^^^^^^^^^^^

``max_query_size``: The maximum number of documents that will be downloaded from Elasticsearch in a single query. If you
expect a large number of results, consider using ``use_count_query`` for the rule. If this
limit is reached, a warning will be logged but ElastAlert 2 will continue without downloading more results. This setting will
override a global ``max_query_size``. (Optional, int, default value of global ``max_query_size``)

filter
^^^^^^

``filter``: A list of Elasticsearch query DSL filters that is used to query Elasticsearch. ElastAlert 2 will query Elasticsearch using the format
``{'filter': {'bool': {'must': [config.filter]}}}`` with an additional timestamp range filter.
All of the results of querying with these filters are passed to the ``RuleType`` for analysis.
For more information writing filters, see :ref:`Writing Filters <writingfilters>`. (Required, Elasticsearch query DSL, no default)

include
^^^^^^^

``include``: A list of terms that should be included in query results and passed to rule types and alerts. When set, only those
fields, along with '@timestamp', ``query_key``, ``compare_key``, and ``top_count_keys``  are included, if present.
(Optional, list of strings, default all fields)

top_count_keys
^^^^^^^^^^^^^^

``top_count_keys``: A list of fields. ElastAlert 2 will perform a terms query for the top X most common values for each of the fields,
where X is 5 by default, or ``top_count_number`` if it exists.
For example, if ``num_events`` is 100, and ``top_count_keys`` is ``- "username"``, the alert will say how many of the 100 events
have each username, for the top 5 usernames. When this is computed, the time range used is from ``timeframe`` before the most recent event
to 10 minutes past the most recent event. Because ElastAlert 2 uses an aggregation query to compute this, it will attempt to use the
field name plus ".raw" to count unanalyzed terms. To turn this off, set ``raw_count_keys`` to false.

top_count_number
^^^^^^^^^^^^^^^^

``top_count_number``: The number of terms to list if ``top_count_keys`` is set. (Optional, integer, default 5)

raw_count_keys
^^^^^^^^^^^^^^

``raw_count_keys``: If true, all fields in ``top_count_keys`` will have ``.raw`` appended to them. (Optional, boolean, default true)

description
^^^^^^^^^^^

``description``: text describing the purpose of rule. (Optional, string, default empty string)
Can be referenced in custom alerters to provide context as to why a rule might trigger.

generate_kibana_link
^^^^^^^^^^^^^^^^^^^^

``generate_kibana_link``: This option is for Kibana 3 only.
If true, ElastAlert 2 will generate a temporary Kibana dashboard and include a link to it in alerts. The dashboard
consists of an events over time graph and a table with ``include`` fields selected in the table. If the rule uses ``query_key``, the
dashboard will also contain a filter for the ``query_key`` of the alert. The dashboard schema will
be uploaded to the kibana-int index as a temporary dashboard. (Optional, boolean, default False)

kibana_url
^^^^^^^^^^

``kibana_url``: The base url of the Kibana application. If not specified, a URL will be constructed using ``es_host``
and ``es_port``.

This value will be used if one of the following conditions are met:

- ``generate_kibana_link`` is true
- ``use_kibana_dashboard`` is true
- ``use_kibana4_dashboard`` is true
- ``generate_kibana_discover_url`` is true and ``kibana_discover_app_url`` is a relative path

(Optional, string, default ``http://<es_host>:<es_port>/_plugin/kibana/``)

kibana_username
^^^^^^^^^^^^^^^

``kibana_username``: The username used to make basic authenticated API requests against Kibana.
This value is only used if ``shorten_kibana_discover_url`` is true.

(Optional, string, no default)

kibana_password
^^^^^^^^^^^^^^^

``kibana_password``: The password used to make basic authenticated API requests against Kibana.
This value is only used if ``shorten_kibana_discover_url`` is true.

(Optional, string, no default)

use_kibana_dashboard
^^^^^^^^^^^^^^^^^^^^

``use_kibana_dashboard``: The name of a Kibana 3 dashboard to link to. Instead of generating a dashboard from a template,
ElastAlert 2 can use an existing dashboard. It will set the time range on the dashboard to around the match time,
upload it as a temporary dashboard, add a filter to the ``query_key`` of the alert if applicable,
and put the url to the dashboard in the alert. (Optional, string, no default)

use_kibana4_dashboard
^^^^^^^^^^^^^^^^^^^^^

``use_kibana4_dashboard``: A link to a Kibana 4 dashboard. For example, "https://kibana.example.com/#/dashboard/My-Dashboard".
This will set the time setting on the dashboard from the match time minus the timeframe, to 10 minutes after the match time.
Note that this does not support filtering by ``query_key`` like Kibana 3.  This value can use `$VAR` and `${VAR}` references
to expand environment variables.

kibana4_start_timedelta
^^^^^^^^^^^^^^^^^^^^^^^

``kibana4_start_timedelta``: Defaults to 10 minutes. This option allows you to specify the start time for the generated kibana4 dashboard.
This value is added in front of the event. For example,

``kibana4_start_timedelta: minutes: 2``

kibana4_end_timedelta
^^^^^^^^^^^^^^^^^^^^^

``kibana4_end_timedelta``: Defaults to 10 minutes. This option allows you to specify the end time for the generated kibana4 dashboard.
This value is added in back of the event. For example,

``kibana4_end_timedelta: minutes: 2``

generate_kibana_discover_url
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``generate_kibana_discover_url``: Enables the generation of the ``kibana_discover_url`` variable for the Kibana Discover application.
This setting requires the following settings are also configured:

- ``kibana_discover_app_url``
- ``kibana_discover_version``
- ``kibana_discover_index_pattern_id``

``generate_kibana_discover_url: true``

Example usage::

    generate_kibana_discover_url: True
    kibana_discover_app_url: "http://localhost:5601/app/discover#/"
    kibana_discover_index_pattern_id: "4babf380-c3b1-11eb-b616-1b59c2feec54"
    kibana_discover_version: "7.15"
    kibana_discover_from_timedelta:
      minutes: 10
    kibana_discover_to_timedelta:
      minutes: 10
    alert_text: '{0}'
    alert_text_args: [ kibana_discover_url ]
    alert_text_type: alert_text_only

shorten_kibana_discover_url
^^^^^^^^^^^^^^^^^^^^^^^^^^^

``shorten_kibana_discover_url``: Enables the shortening of the generated Kibana Discover urls.
In order to use the Kibana Shorten URL REST API, the ``kibana_discover_app_url`` must be provided
as a relative url (e.g. app/discover?#/).

ElastAlert may need to authenticate with Kibana to invoke the Kibana Shorten URL REST API. The
supported authentication methods are:

- Basic authentication by specifying ``kibana_username`` and ``kibana_password``
- AWS authentication (if configured already for ElasticSearch)

(Optional, bool, false)

kibana_discover_app_url
^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_app_url``: The url of the Kibana Discover application used to generate the ``kibana_discover_url`` variable.
This value can use `$VAR` and `${VAR}` references to expand environment variables.
This value should be relative to the base kibana url defined by ``kibana_url`` and will vary depending on your installation.

``kibana_discover_app_url: app/discover#/``

(Optional, string, no default)

kibana_discover_security_tenant
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_security_tenant``: The Kibana security tenant to include in the generated
``kibana_discover_url`` variable.

(Optional, string, no default)

kibana_discover_version
^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_version``: Specifies the version of the Kibana Discover application.

The currently supported versions of Kibana Discover are:

- `5.6`
- `6.0`, `6.1`, `6.2`, `6.3`, `6.4`, `6.5`, `6.6`, `6.7`, `6.8`
- `7.0`, `7.1`, `7.2`, `7.3`, `7.4`, `7.5`, `7.6`, `7.7`, `7.8`, `7.9`, `7.10`, `7.11`, `7.12`, `7.13`, `7.14`, `7.15`

``kibana_discover_version: '7.15'``

kibana_discover_index_pattern_id
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_index_pattern_id``: The id of the index pattern to link to in the Kibana Discover application.
These ids are usually generated and can be found in url of the index pattern management page, or by exporting its saved object.

Example export of an index pattern's saved object:

.. code-block:: text

    [
        {
            "_id": "4e97d188-8a45-4418-8a37-07ed69b4d34c",
            "_type": "index-pattern",
            "_source": { ... }
        }
    ]

You can modify an index pattern's id by exporting the saved object, modifying the ``_id`` field, and re-importing.

``kibana_discover_index_pattern_id: 4e97d188-8a45-4418-8a37-07ed69b4d34c``

kibana_discover_columns
^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_columns``: The columns to display in the generated Kibana Discover application link.
Defaults to the ``_source`` column.

``kibana_discover_columns: [ timestamp, message ]``

kibana_discover_from_timedelta
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_from_timedelta``:  The offset to the `from` time of the Kibana Discover link's time range.
The `from` time is calculated by subtracting this timedelta from the event time.  Defaults to 10 minutes.

``kibana_discover_from_timedelta: minutes: 2``

kibana_discover_to_timedelta
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``kibana_discover_to_timedelta``:  The offset to the `to` time of the Kibana Discover link's time range.
The `to` time is calculated by adding this timedelta to the event time.  Defaults to 10 minutes.

``kibana_discover_to_timedelta: minutes: 2``

use_local_time
^^^^^^^^^^^^^^

``use_local_time``: Whether to convert timestamps to the local time zone in alerts. If false, timestamps will
be converted to UTC, which is what ElastAlert 2 uses internally. (Optional, boolean, default true)

match_enhancements
^^^^^^^^^^^^^^^^^^

``match_enhancements``: A list of enhancement modules to use with this rule. An enhancement module is a subclass of enhancements.BaseEnhancement
that will be given the match dictionary and can modify it before it is passed to the alerter. The enhancements will be run after silence and realert
is calculated and in the case of aggregated alerts, right before the alert is sent. This can be changed by setting ``run_enhancements_first``.
The enhancements should be specified as
``module.file.EnhancementName``. See :ref:`Enhancements` for more information. (Optional, list of strings, no default)

run_enhancements_first
^^^^^^^^^^^^^^^^^^^^^^

``run_enhancements_first``: If set to true, enhancements will be run as soon as a match is found. This means that they can be changed
or dropped before affecting realert or being added to an aggregation. Silence stashes will still be created before the
enhancement runs, meaning even if a ``DropMatchException`` is raised, the rule will still be silenced. (Optional, boolean, default false)

query_key
^^^^^^^^^

``query_key``: Having a query key means that realert time will be counted separately for each unique value of ``query_key``. For rule types which
count documents, such as spike, frequency and flatline, it also means that these counts will be independent for each unique value of ``query_key``.
For example, if ``query_key`` is set to ``username`` and ``realert`` is set, and an alert triggers on a document with ``{'username': 'bob'}``,
additional alerts for ``{'username': 'bob'}`` will be ignored while other usernames will trigger alerts. Documents which are missing the
``query_key`` will be grouped together. A list of fields may also be used, which will create a compound query key. This compound key is
treated as if it were a single field whose value is the component values, or "None", joined by commas. A new field with the key
"field1,field2,etc" will be created in each document and may conflict with existing fields of the same name.

aggregation_key
^^^^^^^^^^^^^^^

``aggregation_key``: Having an aggregation key in conjunction with an aggregation will make it so that each new value encountered for the aggregation_key field will result in a new, separate aggregation window.

summary_table_fields
^^^^^^^^^^^^^^^^^^^^

``summary_table_fields``: Specifying the summmary_table_fields in conjunction with an aggregation will make it so that each aggregated alert will contain a table summarizing the values for the specified fields in all the matches that were aggregated together.

summary_table_type
^^^^^^^^^^^^^^^^^^^^

``summary_table_type``: Either ``ascii`` or ``markdown``. Select the table type to use for the aggregation summary. Defaults to ``ascii`` for the classical text based table.

summary_table_max_rows
^^^^^^^^^^^^^^^^^^^^^^

``summary_table_max_rows``: Limit the maximum number of rows that will be shown in the summary table.

summary_prefix
^^^^^^^^^^^^^^^^^^^^

``summary_prefix``: Specify a prefix string, which will be added in front of the aggregation summary table. This string is currently not subject to any formatting.

summary_suffix
^^^^^^^^^^^^^^^^^^^^

``summary_suffix``: Specify a suffix string, which will be added after the aggregation summary table. This string is currently not subject to any formatting.

timestamp_type
^^^^^^^^^^^^^^

``timestamp_type``: One of ``iso``, ``unix``, ``unix_ms``, ``custom``. This option will set the type of ``@timestamp`` (or ``timestamp_field``)
used to query Elasticsearch. ``iso`` will use ISO8601 timestamps, which will work with most Elasticsearch date type field. ``unix`` will
query using an integer unix (seconds since 1/1/1970) timestamp. ``unix_ms`` will use milliseconds unix timestamp. ``custom`` allows you to define
your own ``timestamp_format``. The default is ``iso``.
(Optional, string enum, default iso).

timestamp_format
^^^^^^^^^^^^^^^^

``timestamp_format``: In case Elasticsearch used custom date format for date type field, this option provides a way to define custom timestamp
format to match the type used for Elastisearch date type field. This option is only valid if ``timestamp_type`` set to ``custom``.
(Optional, string, default '%Y-%m-%dT%H:%M:%SZ').

timestamp_format_expr
^^^^^^^^^^^^^^^^^^^^^

``timestamp_format_expr``: In case Elasticsearch used custom date format for date type field, this option provides a way to adapt the
value obtained converting a datetime through ``timestamp_format``, when the format cannot match perfectly what defined in Elastisearch.
When set, this option is evaluated as a Python expression along with a *globals* dictionary containing the original datetime instance
named ``dt`` and the timestamp to be refined, named ``ts``. The returned value becomes the timestamp obtained from the datetime.
For example, when the date type field in Elasticsearch uses milliseconds (``yyyy-MM-dd'T'HH:mm:ss.SSS'Z'``) and ``timestamp_format``
option is ``'%Y-%m-%dT%H:%M:%S.%fZ'``, Elasticsearch would fail to parse query terms as they contain microsecond values - that is
it gets 6 digits instead of 3 - since the ``%f`` placeholder stands for microseconds for Python *strftime* method calls.
Setting ``timestamp_format_expr: 'ts[:23] + ts[26:]'`` will truncate the value to milliseconds granting Elasticsearch compatibility.
This option is only valid if ``timestamp_type`` set to ``custom``.
(Optional, string, no default).

_source_enabled
^^^^^^^^^^^^^^^

``_source_enabled``: If true, ElastAlert 2 will use _source to retrieve fields from documents in Elasticsearch. If false,
ElastAlert 2 will use ``fields`` to retrieve stored fields. Both of these are represented internally as if they came from ``_source``.
See https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-fields.html for more details. The fields used come from ``include``,
see above for more details. (Optional, boolean, default True)

scan_entire_timeframe
^^^^^^^^^^^^^^^^^^^^^

``scan_entire_timeframe``: If true, when ElastAlert 2 starts, it will always start querying at the current time minus the timeframe.
``timeframe`` must exist in the rule. This may be useful, for example, if you are using a flatline rule type with a large timeframe,
and you want to be sure that if ElastAlert 2 restarts, you can still get alerts. This may cause duplicate alerts for some rule types,
for example, Frequency can alert multiple times in a single timeframe, and if ElastAlert 2 were to restart with this setting, it may
scan the same range again, triggering duplicate alerts.

Some rules and alerts require additional options, which also go in the top level of the rule configuration file.

query_timezone
^^^^^^^^^^^^^^

``query_timezone``: Whether to convert UTC time to the specified time zone in rule queries.
If not set, start and end time of query will be used UTC. (Optional, string, default empty string)

Example value : query_timezone: "Europe/Istanbul"

.. _testing :

Testing Your Rule
=================

Once you've written a rule configuration, you will want to validate it. To do so, you can either run ElastAlert 2 in debug mode,
or use ``elastalert-test-rule``, which is a script that makes various aspects of testing easier.

It can:

- Check that the configuration file loaded successfully.

- Check that the Elasticsearch filter parses.

- Run against the last X day(s) and the show the number of hits that match your filter.

- Show the available terms in one of the results.

- Save documents returned to a JSON file.

- Run ElastAlert 2 using either a JSON file or actual results from Elasticsearch.

- Print out debug alerts or trigger real alerts.

- Check that, if they exist, the primary_key, compare_key and include terms are in the results.

- Show what metadata documents would be written to ``elastalert_status``.

Without any optional arguments, it will run ElastAlert 2 over the last 24 hours and print out any alerts that would have occurred.
Here is an example test run which triggered an alert:

.. code-block:: console

    $ elastalert-test-rule my_rules/rule1.yaml
    Successfully Loaded Example rule1

    Got 105 hits from the last 1 day

    Available terms in first hit:
        @timestamp
        field1
        field2
        ...
    Included term this_field_doesnt_exist may be missing or null

    INFO:root:Queried rule Example rule1 from 6-16 15:21 PDT to 6-17 15:21 PDT: 105 hits
    INFO:root:Alert for Example rule1 at 2015-06-16T23:53:12Z:
    INFO:root:Example rule1

    At least 50 events occurred between 6-16 18:30 PDT and 6-16 20:30 PDT

    field1:
    value1: 25
    value2: 25

    @timestamp: 2015-06-16T20:30:04-07:00
    field1: value1
    field2: something


    Would have written the following documents to elastalert_status:

    silence - {'rule_name': 'Example rule1', '@timestamp': datetime.datetime( ... ), 'exponent': 0, 'until':
    datetime.datetime( ... )}

    elastalert_status - {'hits': 105, 'matches': 1, '@timestamp': datetime.datetime( ... ), 'rule_name': 'Example rule1',
    'starttime': datetime.datetime( ... ), 'endtime': datetime.datetime( ... ), 'time_taken': 3.1415926}

Note that everything between "Alert for Example rule1 at ..." and "Would have written the following ..." is the exact text body that an alert would have.
See the section below on alert content for more details.
Also note that datetime objects are converted to ISO8601 timestamps when uploaded to Elasticsearch. See :ref:`the section on metadata <metadata>` for more details.

Other options include:

``--schema-only``: Only perform schema validation on the file. It will not load modules or query Elasticsearch. This may catch invalid YAML
and missing or misconfigured fields.

``--count-only``: Only find the number of matching documents and list available fields. ElastAlert 2 will not be run and documents will not be downloaded.

``--days N``: Instead of the default 1 day, query N days. For selecting more specific time ranges, you must run ElastAlert 2 itself and use ``--start``
and ``--end``.

``--save-json FILE``: Save all documents downloaded to a file as JSON. This is useful if you wish to modify data while testing or do offline
testing in conjunction with ``--data FILE``. A maximum of 10,000 documents will be downloaded.

``--data FILE``: Use a JSON file as a data source instead of Elasticsearch. The file should be a single list containing objects,
rather than objects on separate lines. Note than this uses mock functions which mimic some Elasticsearch query methods and is not
guaranteed to have the exact same results as with Elasticsearch. For example, analyzed string fields may behave differently.

``--alert``: Trigger real alerts instead of the debug (logging text) alert.

``--formatted-output``: Output results in formatted JSON.

.. note::
   Results from running this script may not always be the same as if an actual ElastAlert 2 instance was running. Some rule types, such as spike
   and flatline require a minimum elapsed time before they begin alerting, based on their timeframe. In addition, use_count_query and
   use_terms_query rely on run_every to determine their resolution. This script uses a fixed 5 minute window, which is the same as the default.


.. _ruletypes:

Rule Types
==========

The various ``RuleType`` classes, defined in ``elastalert/ruletypes.py``, form the main logic behind ElastAlert 2. An instance
is held in memory for each rule, passed all of the data returned by querying Elasticsearch with a given filter, and generates
matches based on that data.

To select a rule type, set the ``type`` option to the name of the rule type in the rule configuration file:

``type: <rule type>``

Any
~~~

``any``: The any rule will match everything. Every hit that the query returns will generate an alert.

Blacklist
~~~~~~~~~

``blacklist``: The blacklist rule will check a certain field against a blacklist, and match if it is in the blacklist.

This rule requires two additional options:

``compare_key``: The name of the field to use to compare to the blacklist. If the field is null, those events will be ignored.

``blacklist``: A list of blacklisted values, and/or a list of paths to flat files which contain the blacklisted values using ``- "!file /path/to/file"``; for example::

    blacklist:
        - value1
        - value2
        - "!file /tmp/blacklist1.txt"
        - "!file /tmp/blacklist2.txt"

It is possible to mix between blacklist value definitions, or use either one. The ``compare_key`` term must be equal to one of these values for it to match.

Whitelist
~~~~~~~~~

``whitelist``: Similar to ``blacklist``, this rule will compare a certain field to a whitelist, and match if the list does not contain
the term.

This rule requires three additional options:

``compare_key``: The name of the field to use to compare to the whitelist.

``ignore_null``: If true, events without a ``compare_key`` field will not match.

``whitelist``: A list of whitelisted values, and/or a list of paths to flat files which contain the whitelisted values using  ``- "!file /path/to/file"``; for example::

    whitelist:
        - value1
        - value2
        - "!file /tmp/whitelist1.txt"
        - "!file /tmp/whitelist2.txt"

It is possible to mix between whitelisted value definitions, or use either one. The ``compare_key`` term must be in this list or else it will match.

Change
~~~~~~

For an example configuration file using this rule type, look at ``examples/rules/example_change.yaml``.

``change``: This rule will monitor a certain field and match if that field changes. The field
must change with respect to the last event with the same ``query_key``.

This rule requires three additional options:

``compare_key``: The names of the field to monitor for changes. Since this is a list of strings, we can
have multiple keys. An alert will trigger if any of the fields change.

``ignore_null``: If true, events without a ``compare_key`` field will not count as changed. Currently this checks for all the fields in ``compare_key``

``query_key``: This rule is applied on a per-``query_key`` basis. This field must be present in all of
the events that are checked.

There is also an optional field:

``timeframe``: The maximum time between changes. After this time period, ElastAlert 2 will forget the old value
of the ``compare_key`` field.

Frequency
~~~~~~~~~

For an example configuration file using this rule type, look at ``examples/rules/example_frequency.yaml``.

``frequency``: This rule matches when there are at least a certain number of events in a given time frame. This
may be counted on a per-``query_key`` basis.

This rule requires two additional options:

``num_events``: The number of events which will trigger an alert, inclusive.

``timeframe``: The time that ``num_events`` must occur within.

Optional:

``use_count_query``: If true, ElastAlert 2 will poll Elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. ``doc_type`` must be set to use this.

``doc_type``: Specify the ``_type`` of document to search for. This must be present if ``use_count_query`` or ``use_terms_query`` is set.

``use_terms_query``: If true, ElastAlert 2 will make an aggregation query against Elasticsearch to get counts of documents matching
each unique value of ``query_key``. This must be used with ``query_key`` and ``doc_type``. This will only return a maximum of ``terms_size``,
default 50, unique terms.

``terms_size``: When used with ``use_terms_query``, this is the maximum number of terms returned per query. Default is 50.

``query_key``: Counts of documents will be stored independently for each value of ``query_key``. Only ``num_events`` documents,
all with the same value of ``query_key``, will trigger an alert.


``attach_related``: Will attach all the related events to the event that triggered the frequency alert. For example in an alert triggered with ``num_events``: 3,
the 3rd event will trigger the alert on itself and add the other 2 events in a key named ``related_events`` that can be accessed in the alerter.

Spike
~~~~~

``spike``: This rule matches when the volume of events during a given time period is ``spike_height`` times larger or smaller
than during the previous time period. It uses two sliding windows to compare the current and reference frequency
of events. We will call this two windows "reference" and "current".

This rule requires three additional options:

``spike_height``: The ratio of number of events in the last ``timeframe`` to the previous ``timeframe`` that when hit
will trigger an alert.

``spike_type``: Either 'up', 'down' or 'both'. 'Up' meaning the rule will only match when the number of events is ``spike_height`` times
higher. 'Down' meaning the reference number is ``spike_height`` higher than the current number. 'Both' will match either.

``timeframe``: The rule will average out the rate of events over this time period. For example, ``hours: 1`` means that the 'current'
window will span from present to one hour ago, and the 'reference' window will span from one hour ago to two hours ago. The rule
will not be active until the time elapsed from the first event is at least two timeframes. This is to prevent an alert being triggered
before a baseline rate has been established. This can be overridden using ``alert_on_new_data``.


Optional:

``field_value``: When set, uses the value of the field in the document and not the number of matching documents.
This is useful to monitor for example a temperature sensor and raise an alarm if the temperature grows too fast.
Note that the means of the field on the reference and current windows are used to determine if the ``spike_height`` value is reached.
Note also that the threshold parameters are ignored in this mode.


``threshold_ref``: The minimum number of events that must exist in the reference window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_ref: 10``, then the 'reference' window must contain at least 10 events and the 'current' window at
least three times that for an alert to be triggered.

``threshold_cur``: The minimum number of events that must exist in the current window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_cur: 60``, then an alert will occur if the current window has more than 60 events and
the reference window has less than a third as many.

To illustrate the use of ``threshold_ref``, ``threshold_cur``, ``alert_on_new_data``, ``timeframe`` and ``spike_height`` together,
consider the following examples::

    " Alert if at least 15 events occur within two hours and less than a quarter of that number occurred within the previous two hours. "
    timeframe: hours: 2
    spike_height: 4
    spike_type: up
    threshold_cur: 15

    hour1: 5 events (ref: 0, cur: 5) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour2: 5 events (ref: 0, cur: 10) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour3: 10 events (ref: 5, cur: 15) - No alert because (a) spike_height not met, (b) ref window not filled
    hour4: 35 events (ref: 10, cur: 45) - Alert because (a) spike_height met, (b) threshold_cur met, (c) ref window filled

    hour1: 20 events (ref: 0, cur: 20) - No alert because ref window not filled
    hour2: 21 events (ref: 0, cur: 41) - No alert because ref window not filled
    hour3: 19 events (ref: 20, cur: 40) - No alert because (a) spike_height not met, (b) ref window not filled
    hour4: 23 events (ref: 41, cur: 42) - No alert because spike_height not met

    hour1: 10 events (ref: 0, cur: 10) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour2: 0 events (ref: 0, cur: 10) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour3: 0 events (ref: 10, cur: 0) - No alert because (a) threshold_cur not met, (b) ref window not filled, (c) spike_height not met
    hour4: 30 events (ref: 10, cur: 30) - No alert because spike_height not met
    hour5: 5 events (ref: 0, cur: 35) - Alert because (a) spike_height met, (b) threshold_cur met, (c) ref window filled

    " Alert if at least 5 events occur within two hours, and twice as many events occur within the next two hours. "
    timeframe: hours: 2
    spike_height: 2
    spike_type: up
    threshold_ref: 5

    hour1: 20 events (ref: 0, cur: 20) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour2: 100 events (ref: 0, cur: 120) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour3: 100 events (ref: 20, cur: 200) - No alert because ref window not filled
    hour4: 100 events (ref: 120, cur: 200) - No alert because spike_height not met

    hour1: 0 events (ref: 0, cur: 0) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour2: 20 events (ref: 0, cur: 20) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour3: 100 events (ref: 0, cur: 120) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour4: 100 events (ref: 20, cur: 200) - Alert because (a) spike_height met, (b) threshold_ref met, (c) ref window filled

    hour1: 1 events (ref: 0, cur: 1) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour2: 2 events (ref: 0, cur: 3) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour3: 2 events (ref: 1, cur: 4) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour4: 1000 events (ref: 3, cur: 1002) - No alert because threshold_ref not met
    hour5: 2 events (ref: 4, cur: 1002) - No alert because threshold_ref not met
    hour6: 4 events: (ref: 1002, cur: 6) - No alert because spike_height not met

    hour1: 1000 events (ref: 0, cur: 1000) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour2: 0 events (ref: 0, cur: 1000) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour3: 0 events (ref: 1000, cur: 0) - No alert because (a) spike_height not met, (b) ref window not filled
    hour4: 0 events (ref: 1000, cur: 0) - No alert because spike_height not met
    hour5: 1000 events (ref: 0, cur: 1000) - No alert because threshold_ref not met
    hour6: 1050 events (ref: 0, cur: 2050)- No alert because threshold_ref not met
    hour7: 1075 events (ref: 1000, cur: 2125) Alert because (a) spike_height met, (b) threshold_ref met, (c) ref window filled

    " Alert if at least 100 events occur within two hours and less than a fifth of that number occurred in the previous two hours. "
    timeframe: hours: 2
    spike_height: 5
    spike_type: up
    threshold_cur: 100

    hour1: 1000 events (ref: 0, cur: 1000) - No alert because ref window not filled

    hour1: 2 events (ref: 0, cur: 2) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour2: 1 events (ref: 0, cur: 3) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour3: 20 events (ref: 2, cur: 21) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour4: 81 events (ref: 3, cur: 101) - Alert because (a) spike_height met, (b) threshold_cur met, (c) ref window filled

    hour1: 10 events (ref: 0, cur: 10) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour2: 20 events (ref: 0, cur: 30) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour3: 40 events (ref: 10, cur: 60) - No alert because (a) threshold_cur not met, (b) ref window not filled
    hour4: 80 events (ref: 30, cur: 120) - No alert because spike_height not met
    hour5: 200 events (ref: 60, cur: 280) - No alert because spike_height not met

``alert_on_new_data``: This option is only used if ``query_key`` is set. When this is set to true, any new ``query_key`` encountered may
trigger an immediate alert. When set to false, baseline must be established for each new ``query_key`` value, and then subsequent spikes may
cause alerts. Baseline is established after ``timeframe`` has elapsed twice since first occurrence.

``use_count_query``: If true, ElastAlert 2 will poll Elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. ``doc_type`` must be set to use this.

``doc_type``: Specify the ``_type`` of document to search for. This must be present if ``use_count_query`` or ``use_terms_query`` is set.

``use_terms_query``: If true, ElastAlert 2 will make an aggregation query against Elasticsearch to get counts of documents matching
each unique value of ``query_key``. This must be used with ``query_key`` and ``doc_type``. This will only return a maximum of ``terms_size``,
default 50, unique terms.

``terms_size``: When used with ``use_terms_query``, this is the maximum number of terms returned per query. Default is 50.

``query_key``: Counts of documents will be stored independently for each value of ``query_key``.

Flatline
~~~~~~~~

``flatline``: This rule matches when the total number of events is under a given ``threshold`` for a time period.

This rule requires two additional options:

``threshold``: The minimum number of events for an alert not to be triggered.

``timeframe``: The time period that must contain less than ``threshold`` events.

Optional:

``use_count_query``: If true, ElastAlert 2 will poll Elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. ``doc_type`` must be set to use this.

``doc_type``: Specify the ``_type`` of document to search for. This must be present if ``use_count_query`` or ``use_terms_query`` is set.

``use_terms_query``: If true, ElastAlert 2 will make an aggregation query against Elasticsearch to get counts of documents matching
each unique value of ``query_key``. This must be used with ``query_key`` and ``doc_type``. This will only return a maximum of ``terms_size``,
default 50, unique terms.

``terms_size``: When used with ``use_terms_query``, this is the maximum number of terms returned per query. Default is 50.

``query_key``: With flatline rule, ``query_key`` means that an alert will be triggered if any value of ``query_key`` has been seen at least once
and then falls below the threshold.

``forget_keys``: Only valid when used with ``query_key``. If this is set to true, ElastAlert 2 will "forget" about the ``query_key`` value that
triggers an alert, therefore preventing any more alerts for it until it's seen again.

New Term
~~~~~~~~

``new_term``: This rule matches when a new value appears in a field that has never been seen before. When ElastAlert 2 starts, it will
use an aggregation query to gather all known terms for a list of fields.

This rule requires one additional option:

``fields``: A list of fields to monitor for new terms. ``query_key`` will be used if ``fields`` is not set. Each entry in the
list of fields can itself be a list.  If a field entry is provided as a list, it will be interpreted as a set of fields
that compose a composite key used for the ElasticSearch query.

.. note::

   The composite fields may only refer to primitive types, otherwise the initial ElasticSearch query will not properly return
   the aggregation results, thus causing alerts to fire every time the ElastAlert 2 service initially launches with the rule.
   A warning will be logged to the console if this scenario is encountered. However, future alerts will actually work as
   expected after the initial flurry.

Optional:

``terms_window_size``: The amount of time used for the initial query to find existing terms. No term that has occurred within this time frame
will trigger an alert. The default is 30 days.

``window_step_size``: When querying for existing terms, split up the time range into steps of this size. For example, using the default
30 day window size, and the default 1 day step size, 30 invidivdual queries will be made. This helps to avoid timeouts for very
expensive aggregation queries. The default is 1 day.

``alert_on_missing_field``: Whether or not to alert when a field is missing from a document. The default is false.

``use_terms_query``: If true, ElastAlert 2 will use aggregation queries to get terms instead of regular search queries. This is faster
than regular searching if there is a large number of documents. If this is used, you may only specify a single field, and must also set
``query_key`` to that field. Also, note that ``terms_size`` (the number of buckets returned per query) defaults to 50. This means
that if a new term appears but there are at least 50 terms which appear more frequently, it will not be found.

.. note::

  When using use_terms_query, make sure that the field you are using is not analyzed. If it is, the results of each terms
  query may return tokens rather than full values. ElastAlert 2 will by default turn on use_keyword_postfix, which attempts
  to use the non-analyzed version (.keyword or .raw) to gather initial terms. These will not match the partial values and
  result in false positives.

``use_keyword_postfix``: If true, ElastAlert 2 will automatically try to add .keyword (ES5+) or .raw to the fields when making an
initial query. These are non-analyzed fields added by Logstash. If the field used is analyzed, the initial query will return
only the tokenized values, potentially causing false positives. Defaults to true.

Cardinality
~~~~~~~~~~~

``cardinality``: This rule matches when a the total number of unique values for a certain field within a time frame is higher or lower
than a threshold.

This rule requires:

``timeframe``: The time period in which the number of unique values will be counted.

``cardinality_field``: Which field to count the cardinality for.

This rule requires one of the two following options:

``max_cardinality``: If the cardinality of the data is greater than this number, an alert will be triggered. Each new event that
raises the cardinality will trigger an alert.

``min_cardinality``: If the cardinality of the data is lower than this number, an alert will be triggered. The ``timeframe`` must
have elapsed since the first event before any alerts will be sent. When a match occurs, the ``timeframe`` will be reset and must elapse
again before additional alerts.

Optional:

``query_key``: Group cardinality counts by this field. For each unique value of the ``query_key`` field, cardinality will be counted separately.

Metric Aggregation
~~~~~~~~~~~~~~~~~~

``metric_aggregation``: This rule matches when the value of a metric within the calculation window is higher or lower than a threshold. By
default this is ``buffer_time``.

This rule requires:

``metric_agg_key``: This is the name of the field over which the metric value will be calculated. The underlying type of this field must be
supported by the specified aggregation type.  If using a scripted field via ``metric_agg_script``, this is the name for your scripted field

``metric_agg_type``: The type of metric aggregation to perform on the ``metric_agg_key`` field. This must be one of 'min', 'max', 'avg',
'sum', 'cardinality', 'value_count'.

``doc_type``: Specify the ``_type`` of document to search for.

This rule also requires at least one of the two following options:

``max_threshold``: If the calculated metric value is greater than this number, an alert will be triggered. This threshold is exclusive.

``min_threshold``: If the calculated metric value is less than this number, an alert will be triggered. This threshold is exclusive.

Optional:

``query_key``: Group metric calculations by this field. For each unique value of the ``query_key`` field, the metric will be calculated and
evaluated separately against the threshold(s).

``metric_agg_script``: A `Painless` formatted script describing how to calculate your metric on-the-fly::

    metric_agg_key: myScriptedMetric
    metric_agg_script:
        script: doc['field1'].value * doc['field2'].value

``min_doc_count``: The minimum number of events in the current window needed for an alert to trigger.  Used in conjunction with ``query_key``,
this will only consider terms which in their last ``buffer_time`` had at least ``min_doc_count`` records.  Default 1.

``use_run_every_query_size``: By default the metric value is calculated over a ``buffer_time`` sized window. If this parameter is true
the rule will use ``run_every`` as the calculation window.

``allow_buffer_time_overlap``: This setting will only have an effect if ``use_run_every_query_size`` is false and ``buffer_time`` is greater
than ``run_every``. If true will allow the start of the metric calculation window to overlap the end time of a previous run. By default the
start and end times will not overlap, so if the time elapsed since the last run is less than the metric calculation window size, rule execution
will be skipped (to avoid calculations on partial data).

``bucket_interval``: If present this will divide the metric calculation window into ``bucket_interval`` sized segments. The metric value will
be calculated and evaluated against the threshold(s) for each segment. If ``bucket_interval`` is specified then ``buffer_time`` must be a
multiple of ``bucket_interval``. (Or ``run_every`` if ``use_run_every_query_size`` is true).

``sync_bucket_interval``: This only has an effect if ``bucket_interval`` is present. If true it will sync the start and end times of the metric
calculation window to the keys (timestamps) of the underlying date_histogram buckets. Because of the way elasticsearch calculates date_histogram
bucket keys these usually round evenly to nearest minute, hour, day etc (depending on the bucket size). By default the bucket keys are offset to
allign with the time ElastAlert 2 runs, (This both avoid calculations on partial data, and ensures the very latest documents are included).
See: https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-datehistogram-aggregation.html#_offset for a
more comprehensive explaination.

``metric_format_string``: An optional format string applies to the aggregated metric value in the alert match text and match_body. This adds 'metric_{metric_agg_key}_formatted' value to the match_body in addition to raw, unformatted 'metric_{metric_agg_key}' value so that you can use the values for ``alert_subject_args`` and ``alert_text_args``. Must be a valid python format string. Both str.format() and %-format syntax works. For example, "{:.2%}" will format '0.966666667' to '96.67%', and "%.2f" will format '0.966666667' to '0.97'.
See: https://docs.python.org/3.4/library/string.html#format-specification-mini-language


Spike Aggregation
~~~~~~~~~~~~~~~~~~

``spike_aggregation``: This rule matches when the value of a metric within the calculation window is ``spike_height`` times larger or smaller
than during the previous time period. It uses two sliding windows to compare the current and reference metric values.
We will call these two windows "reference" and "current".

This rule requires:

``metric_agg_key``: This is the name of the field over which the metric value will be calculated. The underlying type of this field must be
supported by the specified aggregation type.  If using a scripted field via ``metric_agg_script``, this is the name for your scripted field

``metric_agg_type``: The type of metric aggregation to perform on the ``metric_agg_key`` field. This must be one of 'min', 'max', 'avg',
'sum', 'cardinality', 'value_count'.

``spike_height``: The ratio of the metric value in the last ``timeframe`` to the previous ``timeframe`` that when hit
will trigger an alert.

``spike_type``: Either 'up', 'down' or 'both'. 'Up' meaning the rule will only match when the metric value is ``spike_height`` times
higher. 'Down' meaning the reference metric value is ``spike_height`` higher than the current metric value. 'Both' will match either.

``buffer_time``: The rule will average out the rate of events over this time period. For example, ``hours: 1`` means that the 'current'
window will span from present to one hour ago, and the 'reference' window will span from one hour ago to two hours ago. The rule
will not be active until the time elapsed from the first event is at least two timeframes. This is to prevent an alert being triggered
before a baseline rate has been established. This can be overridden using ``alert_on_new_data``.

Optional:

``query_key``: Group metric calculations by this field. For each unique value of the ``query_key`` field, the metric will be calculated and
evaluated separately against the 'reference'/'current' metric value and ``spike height``.

``metric_agg_script``: A `Painless` formatted script describing how to calculate your metric on-the-fly::

    metric_agg_key: myScriptedMetric
    metric_agg_script:
        script: doc['field1'].value * doc['field2'].value

``threshold_ref``: The minimum value of the metric in the reference window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_ref: 10``, then the 'reference' window must have a metric value of 10 and the 'current' window at
least three times that for an alert to be triggered.

``threshold_cur``: The minimum value of the metric in the current window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_cur: 60``, then an alert will occur if the current window has a metric value greater than 60 and
the reference window is less than a third of that value.

``min_doc_count``: The minimum number of events in the current window needed for an alert to trigger.  Used in conjunction with ``query_key``,
this will only consider terms which in their last ``buffer_time`` had at least ``min_doc_count`` records.  Default 1.

Percentage Match
~~~~~~~~~~~~~~~~

``percentage_match``: This rule matches when the percentage of document in the match bucket within a calculation window is higher or lower
than a threshold. By default the calculation window is ``buffer_time``.

This rule requires:

``match_bucket_filter``: ES filter DSL. This defines a filter for the match bucket, which should match a subset of the documents returned by the
main query filter.

``doc_type``: Specify the ``_type`` of document to search for.

This rule also requires at least one of the two following options:

``min_percentage``: If the percentage of matching documents is less than this number, an alert will be triggered.

``max_percentage``: If the percentage of matching documents is greater than this number, an alert will be triggered.

Optional:

``query_key``: Group percentage by this field. For each unique value of the ``query_key`` field, the percentage will be calculated and
evaluated separately against the threshold(s).

``use_run_every_query_size``: See ``use_run_every_query_size`` in  Metric Aggregation rule

``allow_buffer_time_overlap``:  See ``allow_buffer_time_overlap`` in  Metric Aggregation rule

``bucket_interval``: See ``bucket_interval`` in  Metric Aggregation rule

``sync_bucket_interval``: See ``sync_bucket_interval`` in  Metric Aggregation rule

``percentage_format_string``: An optional format string applies to the percentage value in the alert match text and match_body. This adds 'percentage_formatted' value to the match_body in addition to raw, unformatted 'percentage' value so that you can use the values for ``alert_subject_args`` and ``alert_text_args``. Must be a valid python format string. Both str.format() and %-format syntax works. For example, both "{:.2f}" and "%.2f" will format '96.6666667' to '96.67'.
See: https://docs.python.org/3.4/library/string.html#format-specification-mini-language

``min_denominator``: Minimum number of documents on which percentage calculation will apply. Default is 0.

.. _alerts:

Alerts
======

Each rule may have any number of alerts attached to it. Alerts are subclasses of ``Alerter`` and are passed
a dictionary, or list of dictionaries, from ElastAlert 2 which contain relevant information. They are configured
in the rule configuration file similarly to rule types.

To set the alerts for a rule, set the ``alert`` option to the name of the alert, or a list of the names of alerts:

``alert: email``

or

.. code-block:: yaml

    alert:
    - email
    - jira

Options for each alerter can either defined at the top level of the YAML file, or nested within the alert name, allowing for different settings
for multiple of the same alerter. For example, consider sending multiple emails, but with different 'To' and 'From' fields:

.. code-block:: yaml

    alert:
     - email
    from_addr: "no-reply@example.com"
    email: "customer@example.com"

versus

.. code-block:: yaml

    alert:
     - email:
         from_addr: "no-reply@example.com"
         email: "customer@example.com"
     - email:
         from_addr: "elastalert@example.com""
         email: "devs@example.com"

If multiple of the same alerter type are used, top level settings will be used as the default and inline settings will override those
for each alerter.

Alert Subject
~~~~~~~~~~~~~

E-mail subjects, Jira issue summaries, PagerDuty alerts, or any alerter that has a "subject" can be customized by adding an ``alert_subject``
that contains a custom summary.
It can be further formatted using standard Python formatting syntax::

    alert_subject: "Issue {0} occurred at {1}"

The arguments for the formatter will be fed from the matched objects related to the alert.
The field names whose values will be used as the arguments can be passed with ``alert_subject_args``::


    alert_subject_args:
    - issue.name
    - "@timestamp"

It is mandatory to enclose the ``@timestamp`` field in quotes since in YAML format a token cannot begin with the ``@`` character. Not using the quotation marks will trigger a YAML parse error.

In case the rule matches multiple objects in the index, only the first match is used to populate the arguments for the formatter.

If the field(s) mentioned in the arguments list are missing, the email alert will have the text ``alert_missing_value`` in place of its expected value. This will also occur if ``use_count_query`` is set to true.

Alert Content
~~~~~~~~~~~~~

There are several ways to format the body text of the various types of events. In EBNF::

    rule_name           = name
    alert_text          = alert_text
    ruletype_text       = Depends on type
    top_counts_header   = top_count_key, ":"
    top_counts_value    = Value, ": ", Count
    top_counts          = top_counts_header, LF, top_counts_value
    field_values        = Field, ": ", Value

Similarly to ``alert_subject``, ``alert_text`` can be further formatted using Jinja2 Templates or Standard Python Formatting Syntax

1. Jinja Template

By setting ``alert_text_type: alert_text_jinja`` you can use jinja2 templates in ``alert_text`` and ``alert_subject``. ::

    alert_text_type: alert_text_jinja

    alert_text: |
      Alert triggered! *({{num_hits}} Matches!)*
      Something happened with {{username}} ({{email}})
      {{description|truncate}}

Top fields are accessible via `{{field_name}}` or `{{_data['field_name']}}`, `_data` is useful when accessing *fields with dots in their keys*, as Jinja treat dot as a nested field.
If `_data` conflicts with your top level data, use  ``jinja_root_name`` to change its name.

2. Standard Python Formatting Syntax

The field names whose values will be used as the arguments can be passed with ``alert_text_args`` or ``alert_text_kw``.
You may also refer to any top-level rule property in the ``alert_subject_args``, ``alert_text_args``, ``alert_missing_value``, and ``alert_text_kw fields``.  However, if the matched document has a key with the same name, that will take preference over the rule property. ::

    alert_text: "Something happened with {0} at {1}"
    alert_text_type: alert_text_only
    alert_text_args: ["username", "@timestamp"]

By default::

    body                = rule_name

                          [alert_text]

                          ruletype_text

                          {top_counts}

                          {field_values}

With ``alert_text_type: alert_text_only``::

    body                = rule_name

                          alert_text


With ``alert_text_type: alert_text_jinja``::

    body                = rule_name

                          alert_text


With ``alert_text_type: exclude_fields``::

    body                = rule_name

                          [alert_text]

                          ruletype_text

                          {top_counts}

With ``alert_text_type: aggregation_summary_only``::

    body                = rule_name

                          aggregation_summary

ruletype_text is the string returned by RuleType.get_match_str.

field_values will contain every key value pair included in the results from Elasticsearch. These fields include "@timestamp" (or the value of ``timestamp_field``),
every key in ``include``, every key in ``top_count_keys``, ``query_key``, and ``compare_key``. If the alert spans multiple events, these values may
come from an individual event, usually the one which triggers the alert.

When using ``alert_text_args``, you can access nested fields and index into arrays. For example, if your match was ``{"data": {"ips": ["127.0.0.1", "12.34.56.78"]}}``, then by using ``"data.ips[1]"`` in ``alert_text_args``, it would replace value with ``"12.34.56.78"``. This can go arbitrarily deep into fields and will still work on keys that contain dots themselves.

Alerter
~~~~~~~

For all Alerter subclasses, you may reference values from a top-level rule property in your Alerter fields by referring to the property name surrounded by dollar signs. This can be useful when you have rule-level properties that you would like to reference many times in your alert. For example:

Example usage::

    jira_priority: $priority$
    jira_alert_owner: $owner$

Alerta
~~~~~~

Alerta alerter will post an alert in the Alerta server instance through the alert API endpoint.
See https://docs.alerta.io/en/latest/api/alert.html for more details on the Alerta JSON format.

For Alerta 5.0

Required:

``alerta_api_url``: API server URL.

Optional:

``alerta_api_key``: This is the api key for alerta server, sent in an ``Authorization`` HTTP header. If not defined, no Authorization header is sent.

``alerta_use_qk_as_resource``: If true and query_key is present, this will override ``alerta_resource`` field with the ``query_key value`` (Can be useful if ``query_key`` is a hostname).

``alerta_use_match_timestamp``: If true, it will use the timestamp of the first match as the ``createTime`` of the alert. otherwise, the current server time is used.

``alerta_api_skip_ssl``: Defaults to False.

``alert_missing_value``: Text to replace any match field not found when formating strings. Defaults to ``<MISSING_TEXT>``.

The following options dictate the values of the API JSON payload:

``alerta_severity``: Defaults to "warning".

``alerta_timeout``: Defaults 84600 (1 Day).

``alerta_type``: Defaults to "elastalert".

The following options use Python-like string syntax ``{<field>}`` or ``%(<field>)s`` to access parts of the match, similar to the CommandAlerter. Ie: "Alert for {clientip}".
If the referenced key is not found in the match, it is replaced by the text indicated by the option ``alert_missing_value``.

``alerta_resource``: Defaults to "elastalert".

``alerta_service``: Defaults to "elastalert".

``alerta_origin``: Defaults to "elastalert".

``alerta_environment``: Defaults to "Production".

``alerta_group``: Defaults to "".

``alerta_correlate``: Defaults to an empty list.

``alerta_tags``: Defaults to an empty list.

``alerta_event``: Defaults to the rule's name.

``alerta_text``: Defaults to the rule's text according to its type.

``alerta_value``: Defaults to "".

The ``attributes`` dictionary is built by joining the lists from  ``alerta_attributes_keys`` and ``alerta_attributes_values``, considered in order.


Example usage using old-style format::

    alert:
      - alerta
    alerta_api_url: "http://youralertahost/api/alert"
    alerta_attributes_keys:   ["hostname",   "TimestampEvent",  "senderIP" ]
    alerta_attributes_values: ["%(key)s",    "%(logdate)s",     "%(sender_ip)s"  ]
    alerta_correlate: ["ProbeUP","ProbeDOWN"]
    alerta_event: "ProbeUP"
    alerta_text:  "Probe %(hostname)s is UP at %(logdate)s GMT"
    alerta_value: "UP"

Example usage using new-style format::

    alert:
      - alerta
    alerta_attributes_values: ["{key}",    "{logdate}",     "{sender_ip}"  ]
    alerta_text:  "Probe {hostname} is UP at {logdate} GMT"

Alertmanager
~~~~~~~~~~~~

This alert type will send alerts to Alertmanager postAlerts. ``alert_subject`` and ``alert_text`` are passed as the annotations labeled ``summary`` and ``description`` accordingly. The labels can be changed.
See https://prometheus.io/docs/alerting/clients/ for more details about the Alertmanager alert format.

Required:

``alertmanager_hosts``: The list of hosts pointing to the Alertmanager.

Optional:

``alertmanager_api_version``: Defaults to `v1`.  Set to `v2` to enable the Alertmanager V2 API postAlerts.

``alertmanager_alertname``: ``alertname`` is the only required label. Defaults to using the rule name of the alert.

``alertmanager_labels``: Key:value pairs of arbitrary labels to be attached to every alert. Keys should match the regular expression ``^[a-zA-Z_][a-zA-Z0-9_]*$``.

``alertmanager_annotations``: Key:value pairs of arbitrary annotations to be attached to every alert. Keys should match the regular expression ``^[a-zA-Z_][a-zA-Z0-9_]*$``.

``alertmanager_fields``: Key:value pairs of labels and corresponding match fields. When using ``alertmanager_fields`` you can access nested fields and index into arrays the same way as with ``alert_text_args``. Keys should match the regular expression ``^[a-zA-Z_][a-zA-Z0-9_]*$``. This dictionary will be merged with the ``alertmanager_labels``.

``alertmanager_alert_subject_labelname``: Rename the annotations' label name for ``alert_subject``. Default is ``summary``.

``alertmanager_alert_text_labelname``: Rename the annotations' label name for ``alert_text``. Default is ``description``.

``alertmanager_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Alertmanager. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``alertmanager_ca_certs``: Set this option to ``True`` if you want to validate the SSL certificate.

``alertmanager_ignore_ssl_errors``: By default ElastAlert 2 will verify SSL certificate. Set this option to ``False`` if you want to ignore SSL errors.

``alertmanager_timeout``: You can specify a timeout value, in seconds, for making communicating with Alertmanager. The default is 10. If a timeout occurs, the alert will be retried next time ElastAlert 2 cycles.

``alertmanager_basic_auth_login``: Basic authentication username.

``alertmanager_basic_auth_password``: Basic authentication password.

Example usage::

  alert:
    - "alertmanager"
  alertmanager_hosts:
    - "http://alertmanager:9093"
  alertmanager_alertname: "Title"
  alertmanager_annotations:
    severity: "error"
  alertmanager_labels:
    source: "elastalert"
  alertmanager_fields:
    msg: "message"
    log: "@log_name"

AWS SES (Amazon Simple Email Service)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The AWS SES alerter is similar to Email alerter but uses AWS SES to send emails. The AWS SES alerter can use AWS credentials
from the rule yaml, standard AWS config files or environment variables.

AWS SES requires one option:

``ses_email``: An address or list of addresses to sent the alert to.

``ses_from_addr``: This sets the From header in the email.

Optional:

``ses_aws_access_key``: An access key to connect to AWS SES with.

``ses_aws_secret_key``: The secret key associated with the access key.

``ses_aws_region``: The AWS region in which the AWS SES resource is located. Default is us-east-1

``ses_aws_profile``: The AWS profile to use. If none specified, the default will be used.

``ses_email_reply_to``: This sets the Reply-To header in the email.

``ses_cc``: This adds the CC emails to the list of recipients. By default, this is left empty.

``ses_bcc``: This adds the BCC emails to the list of recipients but does not show up in the email message. By default, this is left empty.

Example When not using aws_profile usage::

    alert:
      - "ses"
    ses_aws_access_key_id: "XXXXXXXXXXXXXXXXXX'"
    ses_aws_secret_access_key: "YYYYYYYYYYYYYYYYYYYY"
    ses_aws_region: "us-east-1"
    ses_from_addr: "xxxx1@xxx.com"
    ses_email: "xxxx1@xxx.com"

Example When to use aws_profile usage::

    # Create ~/.aws/credentials

    [default]
    aws_access_key_id = xxxxxxxxxxxxxxxxxxxx
    aws_secret_access_key = yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

    # Create ~/.aws/config

    [default]
    region = us-east-1

    # alert rule setting

    alert:
      - "ses"
    ses_aws_profile: "default"
    ses_from_addr: "xxxx1@xxx.com"
    ses_email: "xxxx1@xxx.com"

AWS SNS (Amazon Simple Notification Service)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The AWS SNS alerter will send an AWS SNS notification. The body of the notification is formatted the same as with other alerters.
The AWS SNS alerter uses boto3 and can use credentials in the rule yaml, in a standard AWS credential and config files, or
via environment variables. See http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html for details.

AWS SNS requires one option:

``sns_topic_arn``: The SNS topic's ARN. For example, ``arn:aws:sns:us-east-1:123456789:somesnstopic``

Optional:

``sns_aws_access_key_id``: An access key to connect to SNS with.

``sns_aws_secret_access_key``: The secret key associated with the access key.

``sns_aws_region``: The AWS region in which the SNS resource is located. Default is us-east-1

``sns_aws_profile``: The AWS profile to use. If none specified, the default will be used.

Example When not using aws_profile usage::

    alert:
      - sns
    sns_topic_arn: 'arn:aws:sns:us-east-1:123456789:somesnstopic'
    sns_aws_access_key_id: 'XXXXXXXXXXXXXXXXXX''
    sns_aws_secret_access_key: 'YYYYYYYYYYYYYYYYYYYY'
    sns_aws_region: 'us-east-1' # You must nest aws_region within your alert configuration so it is not used to sign AWS requests.

Example When to use aws_profile usage::

    # Create ~/.aws/credentials

    [default]
    aws_access_key_id = xxxxxxxxxxxxxxxxxxxx
    aws_secret_access_key = yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

    # Create ~/.aws/config

    [default]
    region = us-east-1

    # alert rule setting

    alert:
      - sns
    sns_topic_arn: 'arn:aws:sns:us-east-1:123456789:somesnstopic'
    sns_aws_profile: 'default'

Chatwork
~~~~~~~~

Chatwork will send notification to a Chatwork application. The body of the notification is formatted the same as with other alerters.

Required:

``chatwork_apikey``:  Chatwork API KEY.

``chatwork_room_id``: The ID of the room you are talking to in Chatwork. How to find the room ID is the part of the number after "rid" at the end of the URL of the browser.

``chatwork_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Chatwork. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``chatwork_proxy_login``: The Chatwork proxy auth username.

``chatwork_proxy_pass``: The Chatwork proxy auth password.

Example usage::

    alert:
      - "chatwork"
    chatwork_apikey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    chatwork_room_id: "xxxxxxxxx"

Command
~~~~~~~

The command alert allows you to execute an arbitrary command and pass arguments or stdin from the match. Arguments to the command can use
Python format string syntax to access parts of the match. The alerter will open a subprocess and optionally pass the match, or matches
in the case of an aggregated alert, as a JSON array, to the stdin of the process.

This alert requires one option:

``command``: A list of arguments to execute or a string to execute. If in list format, the first argument is the name of the program to execute. If passed a
string, the command is executed through the shell.

Strings can be formatted using the old-style format (``%``) or the new-style format (``.format()``). When the old-style format is used, fields are accessed
using ``%(field_name)s``, or ``%(field.subfield)s``. When the new-style format is used, fields are accessed using ``{field_name}``. New-style formatting allows accessing nested
fields (e.g., ``{field_1[subfield]}``).

In an aggregated alert, these fields come from the first match.

Optional:

``pipe_match_json``: If true, the match will be converted to JSON and passed to stdin of the command. Note that this will cause ElastAlert 2 to block
until the command exits or sends an EOF to stdout.

``pipe_alert_text``: If true, the standard alert body text will be passed to stdin of the command. Note that this will cause ElastAlert 2 to block
until the command exits or sends an EOF to stdout. It cannot be used at the same time as ``pipe_match_json``.

``fail_on_non_zero_exit``: By default this is ``False``. Allows monitoring of when commands fail to run. When a command returns a non-zero exit status, the alert raises an exception.

Example usage using old-style format::

    alert:
      - command
    command: ["/bin/send_alert", "--username", "%(username)s"]

.. warning::

    Executing commmands with untrusted data can make it vulnerable to shell injection! If you use formatted data in
    your command, it is highly recommended that you use a args list format instead of a shell string.

Example usage using new-style format::

    alert:
      - command
    command: ["/bin/send_alert", "--username", "{match[username]}"]

Datadog
~~~~~~~

This alert will create a `Datadog Event`_. Events are limited to 4000 characters. If an event is sent that contains
a message that is longer than 4000 characters, only his first 4000 characters will be displayed.

This alert requires two additional options:

``datadog_api_key``: `Datadog API key`_

``datadog_app_key``: `Datadog application key`_

Example usage::

    alert:
      - "datadog"
    datadog_api_key: "Datadog API Key"
    datadog_app_key: "Datadog APP Key"

.. _`Datadog Event`: https://docs.datadoghq.com/events/
.. _`Datadog API key`: https://docs.datadoghq.com/account_management/api-app-keys/#api-keys
.. _`Datadog application key`: https://docs.datadoghq.com/account_management/api-app-keys/#application-keys

Debug
~~~~~

The debug alerter will log the alert information using the Python logger at the info level. It is logged into a Python Logger object with the name ``elastalert`` that can be easily accessed using the ``getLogger`` command.

Dingtalk
~~~~~~~~

Dingtalk will send notification to a Dingtalk application. The body of the notification is formatted the same as with other alerters.

Required:

``dingtalk_access_token``:  Dingtalk access token.

``dingtalk_msgtype``:  Dingtalk msgtype, default to ``text``. ``markdown``, ``single_action_card``, ``action_card``.

dingtalk_msgtype single_action_card Required:

``dingtalk_single_title``: The title of a single button..

``dingtalk_single_url``: Jump link for a single button.

dingtalk_msgtype action_card Required:

``dingtalk_btns``:  Button.

dingtalk_msgtype action_card Optional:

``dingtalk_btn_orientation``:  "0": Buttons are arranged vertically "1": Buttons are arranged horizontally.

Example msgtype : text::

    alert:
      - "dingtalk"
    dingtalk_access_token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    dingtalk_msgtype: "text"


Example msgtype : markdown::

    alert:
      - "dingtalk"
    dingtalk_access_token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    dingtalk_msgtype: "markdown"


Example msgtype : single_action_card::

    alert:
      - "dingtalk"
    dingtalk_access_token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    dingtalk_msgtype: "single_action_card"
    dingtalk_single_title: "test3"
    dingtalk_single_url: "https://xxxx.xxx"


Example msgtype : action_card::

    alert:
      - "dingtalk"
    dingtalk_access_token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    dingtalk_msgtype: "action_card"
    dingtalk_btn_orientation: "0"
    dingtalk_btns: [{"title": "a", "actionURL": "https://xxxx1.xxx"}, {"title": "b", "actionURL": "https://xxxx2.xxx"}]

Discord
~~~~~~~

Discord will send notification to a Discord application. The body of the notification is formatted the same as with other alerters.

Required:

``discord_webhook_url``:  The webhook URL.

Optional:

``discord_emoji_title``: By default ElastAlert 2 will use the ``:warning:`` emoji when posting to the channel. You can use a different emoji per ElastAlert 2 rule. Any Apple emoji can be used, see http://emojipedia.org/apple/ . If discord_embed_icon_url parameter is provided, emoji is ignored.

``discord_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Discord. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``discord_proxy_login``: The Discord proxy auth username.

``discord_proxy_password``: The Discord proxy auth username.

``discord_embed_color``: embed color. By default ``0xffffff``.

``discord_embed_footer``: embed footer.

``discord_embed_icon_url``: You can provide icon_url to use custom image. Provide absolute address of the pciture.

Example usage::

    alert:
    - "discord"
    discord_webhook_url: "Your discord webhook url"
    discord_emoji_title: ":lock:"
    discord_embed_color: 0xE24D42
    discord_embed_footer: "Message sent by  from your computer"
    discord_embed_icon_url: "https://humancoders-formations.s3.amazonaws.com/uploads/course/logo/38/thumb_bigger_formation-elasticsearch.png"

Email
~~~~~

This alert will send an email. It connects to an smtp server located at ``smtp_host``, or localhost by default.
If available, it will use STARTTLS.

This alert requires one additional option:

``email``: An address or list of addresses to sent the alert to.

Optional:

``email_from_field``: Use a field from the document that triggered the alert as the recipient. If the field cannot be found,
the ``email`` value will be used as a default. Note that this field will not be available in every rule type, for example, if
you have ``use_count_query`` or if it's ``type: flatline``. You can optionally add a domain suffix to the field to generate the
address using ``email_add_domain``. It can be a single recipient or list of recipients. For example, with the following settings::

    email_from_field: "data.user"
    email_add_domain: "@example.com"

and a match ``{"@timestamp": "2017", "data": {"foo": "bar", "user": "qlo"}}``

an email would be sent to ``qlo@example.com``

``smtp_host``: The SMTP host to use, defaults to localhost.

``smtp_port``: The port to use. Defaults to port 25 when SSL is not used, or 465 when SSL is used.

``smtp_ssl``: Connect the SMTP host using TLS, defaults to ``false``. If ``smtp_ssl`` is not used, ElastAlert 2 will still attempt
STARTTLS.

``smtp_auth_file``: The path to a file which contains SMTP authentication credentials. The path can be either absolute or relative
to the given rule. It should be YAML formatted and contain two fields, ``user`` and ``password``. If this is not present,
no authentication will be attempted.

``smtp_cert_file``: Connect the SMTP host using the given path to a TLS certificate file, default to ``None``.

``smtp_key_file``: Connect the SMTP host using the given path to a TLS key file, default to ``None``.

``email_reply_to``: This sets the Reply-To header in the email. By default, the from address is ElastAlert@ and the domain will be set
by the smtp server.

``from_addr``: This sets the From header in the email. By default, the from address is ElastAlert@ and the domain will be set
by the smtp server.

``cc``: This adds the CC emails to the list of recipients. By default, this is left empty.

``bcc``: This adds the BCC emails to the list of recipients but does not show up in the email message. By default, this is left empty.

``email_format``: If set to 'html', the email's MIME type will be set to HTML, and HTML content should correctly render. If you use this,
you need to put your own HTML into ``alert_text`` and use ``alert_text_type: alert_text_jinja`` Or ``alert_text_type: alert_text_only``.

``assets_dir``: images dir. default to ``/tmp``.

``email_image_keys``: mapping between images keys.

``email_image_values``: mapping between images values

Example assets_dir, email_image_keys, email_image_values::

	assets_dir: "/opt/elastalert/email_images"
	email_image_keys: ["img1"]
	email_image_values: ["my_logo.png"]

Exotel
~~~~~~

Developers in India can use the Exotel alerter, which can send an alert to a mobile phone as an SMS from your ExoPhone. The SMS will contain both the alert name and the specified message body.

The alerter requires the following option:

``exotel_account_sid``: The SID of your Exotel account.

``exotel_auth_token``: The auth token associated with your Exotel account.

Instructions for finding the SID and auth token associated with your account can be found `on the Exotel website
<https://support.exotel.com/support/solutions/articles/3000023019-how-to-find-my-exotel-token-and-exotel-sid>`_.

``exotel_to_number``: The phone number to which you would like to send the alert.

``exotel_from_number``: The ExoPhone number from which the alert will be sent.

The alerter has one optional argument:

``exotel_message_body``: The contents of the SMS. If you don't specify this argument, only the rule name is sent.

Example usage::

    alert:
      - "exotel"
    exotel_account_sid: "Exotel Account SID"
    exotel_auth_token: "Exotel Auth token"
    exotel_to_number: "Exotel to number"
    exotel_from_number: "Exotel from number"

Gitter
~~~~~~

Gitter alerter will send a notification to a predefined Gitter channel. The body of the notification is formatted the same as with other alerters.

The alerter requires the following option:

``gitter_webhook_url``: The webhook URL that includes your auth data and the ID of the channel (room) you want to post to. Go to the Integration Settings
of the channel https://gitter.im/ORGA/CHANNEL#integrations , click 'CUSTOM' and copy the resulting URL.

Optional:

``gitter_msg_level``: By default the alert will be posted with the 'error' level. You can use 'info' if you want the messages to be black instead of red.

``gitter_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Gitter. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

Example usage::

    alert:
      - "gitter"
    gitter_webhook_url: "Your Gitter Webhook URL"
    gitter_msg_level: "error"

GoogleChat
~~~~~~~~~~
GoogleChat alerter will send a notification to a predefined GoogleChat channel. The body of the notification is formatted the same as with other alerters.

The alerter requires the following options:

``googlechat_webhook_url``: The webhook URL that includes the channel (room) you want to post to. Go to the Google Chat website https://chat.google.com and choose the channel in which you wish to receive the notifications. Select 'Configure Webhooks' to create a new webhook or to copy the URL from an existing one. You can use a list of URLs to send to multiple channels.

Optional:

``googlechat_format``: Formatting for the notification. Can be either 'card' or 'basic' (default).

``googlechat_header_title``: Sets the text for the card header title. (Only used if format=card)

``googlechat_header_subtitle``: Sets the text for the card header subtitle. (Only used if format=card)

``googlechat_header_image``: URL for the card header icon. (Only used if format=card)

``googlechat_footer_kibanalink``: URL to Kibana to include in the card footer. (Only used if format=card)

HTTP POST
~~~~~~~~~

This alert type will send results to a JSON endpoint using HTTP POST. The key names are configurable so this is compatible with almost any endpoint. By default, the JSON will contain all the items from the match, unless you specify http_post_payload, in which case it will only contain those items.

Required:

``http_post_url``: The URL to POST.

Optional:

``http_post_payload``: List of keys:values to use as the content of the POST. Example - ip:clientip will map the value from the clientip index of Elasticsearch to JSON key named ip. If not defined, all the Elasticsearch keys will be sent.

``http_post_static_payload``: Key:value pairs of static parameters to be sent, along with the Elasticsearch results. Put your authentication or other information here.

``http_post_headers``: Key:value pairs of headers to be sent as part of the request.

``http_post_proxy``: URL of proxy, if required. only supports https.

``http_post_all_values``: Boolean of whether or not to include every key value pair from the match in addition to those in http_post_payload and http_post_static_payload. Defaults to True if http_post_payload is not specified, otherwise False.

``http_post_timeout``: The timeout value, in seconds, for making the post. The default is 10. If a timeout occurs, the alert will be retried next time elastalert cycles.

``http_post_ca_certs``: Set this option to ``True`` if you want to validate the SSL certificate.

``http_post_ignore_ssl_errors``: By default ElastAlert 2 will verify SSL certificate. Set this option to ``False`` if you want to ignore SSL errors.

Example usage::

    alert: post
    http_post_url: "http://example.com/api"
    http_post_payload:
      ip: clientip
    http_post_static_payload:
      apikey: abc123
    http_post_headers:
      authorization: Basic 123dr3234

HTTP POST 2
~~~~~~~~~~~

This alert type will send results to a JSON endpoint using HTTP POST. The key names are configurable so this is compatible with almost any endpoint. By default, the JSON will contain all the items from the match, unless you specify http_post_payload, in which case it will only contain those items.
This alert is a more flexible version of the HTTP Post alerter.

Required:

``http_post2_url``: The URL to POST.

Optional:

``http_post2_payload``: List of keys:values to use for the payload of the HTTP Post. You can use {{ field }} (Jinja2 template) in the key and the value to reference any field in the matched events (works for nested fields). If not defined, all the Elasticsearch keys will be sent.  Ex: `"description_{{ my_field }}": "Type: {{ type }}\\nSubject: {{ title }}"`

``http_post2_raw_fields``: List of keys:values to use as the content of the POST. Example - ip:clientip will map the value from the clientip field of Elasticsearch to JSON key named ip. This field overwrite the keys with the same name in `http_post2_payload`.

``http_post2_headers``: List of keys:values to use for as headers of the HTTP Post. You can use {{ field }} (Jinja2 template) in the key and the value to reference any field in the matched events (works for nested fields). Ex: `"Authorization": "{{ user }}"`. Headers `"Content-Type": "application/json"` and `"Accept": "application/json;charset=utf-8"` are present by default, you can overwrite them if you think this is necessary.

``http_post2_proxy``: URL of proxy, if required. only supports https.

``http_post2_all_values``: Boolean of whether or not to include every key value pair from the match in addition to those in http_post2_payload and http_post2_static_payload. Defaults to True if http_post2_payload is not specified, otherwise False.

``http_post2_timeout``: The timeout value, in seconds, for making the post. The default is 10. If a timeout occurs, the alert will be retried next time elastalert cycles.

``http_post2_ca_certs``: Set this option to ``True`` if you want to validate the SSL certificate.

``http_post2_ignore_ssl_errors``: By default ElastAlert 2 will verify SSL certificate. Set this option to ``False`` if you want to ignore SSL errors.

Example usage::

    alert: post2
    http_post2_url: "http://example.com/api"
    http_post2_payload:
      description: "An event came from IP {{clientip}}"
      username: "{{user.name}}"
    http_post2_raw_fields:
      ip: clientip
    http_post2_headers:
      authorization: Basic 123dr3234
      X-custom-type: {{type}}

Jira
~~~~

The Jira alerter will open a ticket on Jira whenever an alert is triggered. You must have a service account for ElastAlert 2 to connect with.
The credentials of the service account are loaded from a separate file. The ticket number will be written to the alert pipeline, and if it
is followed by an email alerter, a link will be included in the email.

This alert requires four additional options:

``jira_server``: The hostname of the Jira server.

``jira_project``: The project to open the ticket under.

``jira_issuetype``: The type of issue that the ticket will be filed as. Note that this is case sensitive.

``jira_account_file``: The path to the file which contains Jira account credentials.

For an example Jira account file, see ``examples/rules/jira_acct.yaml``. The account file is also yaml formatted and must contain two fields:

``user``: The username.

``password``: The password.

Optional:

``jira_assignee``: Assigns an issue to a user.

``jira_component``: The name of the component or components to set the ticket to. This can be a single string or a list of strings. This is provided for backwards compatibility and will eventually be deprecated. It is preferable to use the plural ``jira_components`` instead.

``jira_components``: The name of the component or components to set the ticket to. This can be a single string or a list of strings.

``jira_description``: Similar to ``alert_text``, this text is prepended to the Jira description.

``jira_label``: The label or labels to add to the Jira ticket.  This can be a single string or a list of strings. This is provided for backwards compatibility and will eventually be deprecated. It is preferable to use the plural ``jira_labels`` instead.

``jira_labels``: The label or labels to add to the Jira ticket.  This can be a single string or a list of strings.

``jira_priority``: The index of the priority to set the issue to. In the Jira dropdown for priorities, 0 would represent the first priority,
1 the 2nd, etc.

``jira_watchers``: A list of user names to add as watchers on a Jira ticket. This can be a single string or a list of strings.

``jira_bump_tickets``: If true, ElastAlert 2 search for existing tickets newer than ``jira_max_age`` and comment on the ticket with
information about the alert instead of opening another ticket. ElastAlert 2 finds the existing ticket by searching by summary. If the
summary has changed or contains special characters, it may fail to find the ticket. If you are using a custom ``alert_subject``,
the two summaries must be exact matches, except by setting ``jira_ignore_in_title``, you can ignore the value of a field when searching.
For example, if the custom subject is "foo occured at bar", and "foo" is the value field X in the match, you can set ``jira_ignore_in_title``
to "X" and it will only bump tickets with "bar" in the subject. Defaults to false.

``jira_ignore_in_title``: ElastAlert 2 will attempt to remove the value for this field from the Jira subject when searching for tickets to bump.
See ``jira_bump_tickets`` description above for an example.

``jira_max_age``: If ``jira_bump_tickets`` is true, the maximum age of a ticket, in days, such that ElastAlert 2 will comment on the ticket
instead of opening a new one. Default is 30 days.

``jira_bump_not_in_statuses``: If ``jira_bump_tickets`` is true, a list of statuses the ticket must **not** be in for ElastAlert 2 to comment on
the ticket instead of opening a new one. For example, to prevent comments being added to resolved or closed tickets, set this to 'Resolved'
and 'Closed'. This option should not be set if the ``jira_bump_in_statuses`` option is set.

Example usage::

    jira_bump_not_in_statuses:
      - Resolved
      - Closed

``jira_bump_in_statuses``: If ``jira_bump_tickets`` is true, a list of statuses the ticket *must be in* for ElastAlert 2 to comment on
the ticket instead of opening a new one. For example, to only comment on 'Open' tickets  -- and thus not 'In Progress', 'Analyzing',
'Resolved', etc. tickets -- set this to 'Open'. This option should not be set if the ``jira_bump_not_in_statuses`` option is set.

Example usage::

    jira_bump_in_statuses:
      - Open

``jira_bump_only``: Only update if a ticket is found to bump.  This skips ticket creation for rules where you only want to affect existing tickets.

Example usage::

    jira_bump_only: true

``jira_transition_to``: If ``jira_bump_tickets`` is true, Transition this ticket to the given Status when bumping. Must match the text of your Jira implementation's Status field.

Example usage::

    jira_transition_to: 'Fixed'



``jira_bump_after_inactivity``: If this is set, ElastAlert 2 will only comment on tickets that have been inactive for at least this many days.
It only applies if ``jira_bump_tickets`` is true. Default is 0 days.

Arbitrary Jira fields:

ElastAlert 2 supports setting any arbitrary Jira field that your Jira issue supports. For example, if you had a custom field, called "Affected User", you can set it by providing that field name in ``snake_case`` prefixed with ``jira_``.  These fields can contain primitive strings or arrays of strings. Note that when you create a custom field in your Jira server, internally, the field is represented as ``customfield_1111``. In ElastAlert 2, you may refer to either the public facing name OR the internal representation.

In addition, if you would like to use a field in the alert as the value for a custom Jira field, use the field name plus a # symbol in front. For example, if you wanted to set a custom Jira field called "user" to the value of the field "username" from the match, you would use the following.

Example::

    jira_user: "#username"

Example usage::

    jira_arbitrary_singular_field: My Name
    jira_arbitrary_multivalue_field:
      - Name 1
      - Name 2
    jira_customfield_12345: My Custom Value
    jira_customfield_9999:
      - My Custom Value 1
      - My Custom Value 2

Line Notify
~~~~~~~~~~~

Line Notify will send notification to a Line application. The body of the notification is formatted the same as with other alerters.

Required:

``linenotify_access_token``: The access token that you got from https://notify-bot.line.me/my/

Example usage::

    alert:
      - "linenotify"
    linenotify_access_token: "Your linenotify access token"

Mattermost
~~~~~~~~~~

Mattermost alerter will send a notification to a predefined Mattermost channel. The body of the notification is formatted the same as with other alerters.

The alerter requires the following option:

``mattermost_webhook_url``: The webhook URL. Follow the instructions on https://docs.mattermost.com/developer/webhooks-incoming.html to create an incoming webhook on your Mattermost installation.

Optional:

``mattermost_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Mattermost. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``mattermost_ignore_ssl_errors``: By default ElastAlert 2 will verify SSL certificate. Set this option to ``False`` if you want to ignore SSL errors.

``mattermost_username_override``: By default Mattermost will use your username when posting to the channel. Use this option to change it (free text).

``mattermost_channel_override``: Incoming webhooks have a default channel, but it can be overridden. A public channel can be specified "#other-channel", and a Direct Message with "@username".

``mattermost_icon_url_override``: By default ElastAlert 2 will use the default webhook icon when posting to the channel. You can provide icon_url to use custom image.
Provide absolute address of the picture or Base64 data url.

``mattermost_msg_pretext``: You can set the message attachment pretext using this option.

``mattermost_msg_color``: By default the alert will be posted with the 'danger' color. You can also use 'good', 'warning', or hex color code.

``mattermost_msg_fields``: You can add fields to your Mattermost alerts using this option. You can specify the title using `title` and the text value using `value`. Additionally you can specify whether this field should be a `short` field using `short: true`. If you set `args` and `value` is a formattable string, ElastAlert 2 will format the incident key based on the provided array of fields from the rule or match.
See https://docs.mattermost.com/developer/message-attachments.html#fields for more information.

Example mattermost_msg_fields::

    mattermost_msg_fields:
      - title: Stack
        value: "{0} {1}" # interpolate fields mentioned in args
        short: false
        args: ["type", "msg.status_code"] # fields from doc
      - title: Name
        value: static field
        short: false

``mattermost_title``: Sets a title for the message, this shows up as a blue text at the start of the message. Defaults to "".

``mattermost_title_link``: You can add a link in your Mattermost notification by setting this to a valid URL. Requires mattermost_title to be set. Defaults to "".

``mattermost_footer``: Add a static footer text for alert. Defaults to "".

``mattermost_footer_icon``: A Public Url for a footer icon. Defaults to "".

``mattermost_image_url``: An optional URL to an image file (GIF, JPEG, PNG, BMP, or SVG). Defaults to "".

``mattermost_thumb_url``:  An optional URL to an image file (GIF, JPEG, PNG, BMP, or SVG) that is displayed as thumbnail. Defaults to "".

``mattermost_author_name``: An optional name used to identify the author. . Defaults to "".

``mattermost_author_link``: An optional URL used to hyperlink the author_name. Defaults to "".

``mattermost_author_icon``: An optional URL used to display a 16x16 pixel icon beside the author_name. Defaults to "".

``mattermost_attach_kibana_discover_url``: Enables the attachment of the ``kibana_discover_url`` to the mattermost notification. The config ``generate_kibana_discover_url`` must also be ``True`` in order to generate the url. Defaults to ``False``.

``mattermost_kibana_discover_color``: The color of the Kibana Discover url attachment. Defaults to ``#ec4b98``.

``mattermost_kibana_discover_title``: The title of the Kibana Discover url attachment. Defaults to ``Discover in Kibana``.

Example mattermost_attach_kibana_discover_url, mattermost_kibana_discover_color, mattermost_kibana_discover_title::

    # (Required)
    generate_kibana_discover_url: True
    kibana_discover_app_url: "http://localhost:5601/app/discover#/"
    kibana_discover_index_pattern_id: "4babf380-c3b1-11eb-b616-1b59c2feec54"
    kibana_discover_version: "7.15"

    # (Optional)
    kibana_discover_from_timedelta:
      minutes: 10
    kibana_discover_to_timedelta:
      minutes: 10

    # (Required)
    mattermost_attach_kibana_discover_url: True

    # (Optional)
    mattermost_kibana_discover_color: "#ec4b98"
    mattermost_kibana_discover_title: "Discover in Kibana"

Microsoft Teams
~~~~~~~~~~~~~~~

Microsoft Teams alerter will send a notification to a predefined Microsoft Teams channel.

The alerter requires the following options:

``ms_teams_webhook_url``: The webhook URL that includes your auth data and the ID of the channel you want to post to. Go to the Connectors
menu in your channel and configure an Incoming Webhook, then copy the resulting URL. You can use a list of URLs to send to multiple channels.

Optional:

``ms_teams_alert_summary``: Summary should be configured according to `MS documentation <https://docs.microsoft.com/en-us/outlook/actionable-messages/card-reference>`_, although it seems not displayed by Teams currently, defaults to ``ElastAlert Message``.

``ms_teams_theme_color``: By default the alert will be posted without any color line. To add color, set this attribute to a HTML color value e.g. ``#ff0000`` for red.

``ms_teams_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to MS Teams. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``ms_teams_alert_fixed_width``: By default this is ``False`` and the notification will be sent to MS Teams as-is. Teams supports a partial Markdown implementation, which means asterisk, underscore and other characters may be interpreted as Markdown. Currenlty, Teams does not fully implement code blocks. Setting this attribute to ``True`` will enable line by line code blocks. It is recommended to enable this to get clearer notifications in Teams.

Example usage::

    alert:
      - "ms_teams"
    ms_teams_alert_summary: "Alert"
    ms_teams_theme_color: "#6600ff"
    ms_teams_webhook_url: "MS Teams Webhook URL"

OpsGenie
~~~~~~~~

OpsGenie alerter will create an alert which can be used to notify Operations people of issues or log information. An OpsGenie ``API``
integration must be created in order to acquire the necessary ``opsgenie_key`` rule variable. Currently the OpsGenieAlerter only creates
an alert, however it could be extended to update or close existing alerts.

It is necessary for the user to create an OpsGenie Rest HTTPS API `integration page <https://docs.opsgenie.com/docs/alert-api>`_ in order to create alerts.

The OpsGenie alert requires one option:

``opsgenie_key``: The randomly generated API Integration key created by OpsGenie.

Optional:

``opsgenie_account``: The OpsGenie account to integrate with.

``opsgenie_addr``: The OpsGenie URL to to connect against, default is ``https://api.opsgenie.com/v2/alerts``. If using the EU instance of Opsgenie, the URL needs to be ``https://api.eu.opsgenie.com/v2/alerts`` for requests to be successful.

``opsgenie_recipients``: A list OpsGenie recipients who will be notified by the alert.

``opsgenie_recipients_args``: Map of arguments used to format opsgenie_recipients.

``opsgenie_default_receipients``: List of default recipients to notify when the formatting of opsgenie_recipients is unsuccesful.

``opsgenie_teams``: A list of OpsGenie teams to notify (useful for schedules with escalation).

``opsgenie_teams_args``: Map of arguments used to format opsgenie_teams (useful for assigning the alerts to teams based on some data).

``opsgenie_default_teams``: List of default teams to notify when the formatting of opsgenie_teams is unsuccesful.

``opsgenie_tags``: A list of tags for this alert.

``opsgenie_message``: Set the OpsGenie message to something other than the rule name. The message can be formatted with fields from the first match e.g. "Error occurred for {app_name} at {timestamp}.".

``opsgenie_description``: Set the OpsGenie description to something other than the rule body. The message can be formatted with fields from the first match e.g. "Error occurred for {app_name} at {timestamp}.".

``opsgenie_alias``: Set the OpsGenie alias. The alias can be formatted with fields from the first match e.g "{app_name} error".

``opsgenie_subject``: A string used to create the title of the OpsGenie alert. Can use Python string formatting.

``opsgenie_subject_args``: A list of fields to use to format ``opsgenie_subject`` if it contains formaters.

``opsgenie_priority``: Set the OpsGenie priority level. Possible values are P1, P2, P3, P4, P5. Can be formatted with fields from the first match e.g "P{level}"

``opsgenie_details``: Map of custom key/value pairs to include in the alert's details. The value can sourced from either fields in the first match, environment variables, or a constant value.

``opsgenie_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to OpsGenie. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``opsgenie_source``: Set the OpsGenie source, default is `ElastAlert`. Can be formatted with fields from the first match e.g "{source} {region}"

``opsgenie_entity``: Set the OpsGenie entity. Can be formatted with fields from the first match e.g "{host_name}"

Example usage::

    opsgenie_details:
      Author: 'Bob Smith'          # constant value
      Environment: '$VAR'          # environment variable
      Message: { field: message }  # field in the first match

Example opsgenie_details with kibana_discover_url::

    # (Required)
    generate_kibana_discover_url: True
    kibana_discover_app_url: "http://localhost:5601/app/discover#/"
    kibana_discover_index_pattern_id: "4babf380-c3b1-11eb-b616-1b59c2feec54"
    kibana_discover_version: "7.15"

    # (Optional)
    kibana_discover_from_timedelta:
      minutes: 10
    kibana_discover_to_timedelta:
      minutes: 10

    # (Required)
    opsgenie_details:
      Kibana Url: { field: kibana_discover_url }
      Message: { field: message }
      Testing: 'yes'

PagerDuty
~~~~~~~~~

PagerDuty alerter will trigger an incident to a predefined PagerDuty service. The body of the notification is formatted the same as with other alerters.

The alerter requires the following option:

``pagerduty_service_key``: Integration Key generated after creating a service with the 'Use our API directly' option at Integration Settings

``pagerduty_client_name``: The name of the monitoring client that is triggering this event.

``pagerduty_event_type``: Any of the following: `trigger`, `resolve`, or `acknowledge`. (Optional, defaults to `trigger`)

Optional:

``alert_subject``: If set, this will be used as the Incident description within PagerDuty. If not set, ElastAlert 2 will default to using the rule name of the alert for the incident.

``alert_subject_args``: If set, and  ``alert_subject`` is a formattable string, ElastAlert 2 will format the incident key based on the provided array of fields from the rule or match.

``pagerduty_incident_key``: If not set PagerDuty will trigger a new incident for each alert sent. If set to a unique string per rule PagerDuty will identify the incident that this event should be applied.
If there's no open (i.e. unresolved) incident with this key, a new one will be created. If there's already an open incident with a matching key, this event will be appended to that incident's log.

``pagerduty_incident_key_args``: If set, and ``pagerduty_incident_key`` is a formattable string, ElastAlert 2 will format the incident key based on the provided array of fields from the rule or match.

``pagerduty_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to PagerDuty. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

V2 API Options (Optional):

These options are specific to the PagerDuty V2 API

See https://developer.pagerduty.com/docs/events-api-v2/trigger-events/

``pagerduty_api_version``: Defaults to `v1`.  Set to `v2` to enable the PagerDuty V2 Event API.

``pagerduty_v2_payload_class``: Sets the class of the payload. (the event type in PagerDuty)

``pagerduty_v2_payload_class_args``: If set, and ``pagerduty_v2_payload_class`` is a formattable string, ElastAlert 2 will format the class based on the provided array of fields from the rule or match.

``pagerduty_v2_payload_component``: Sets the component of the payload. (what program/interface/etc the event came from)

``pagerduty_v2_payload_component_args``: If set, and ``pagerduty_v2_payload_component`` is a formattable string, ElastAlert 2 will format the component based on the provided array of fields from the rule or match.

``pagerduty_v2_payload_group``: Sets the logical grouping (e.g. app-stack)

``pagerduty_v2_payload_group_args``: If set, and ``pagerduty_v2_payload_group`` is a formattable string, ElastAlert 2 will format the group based on the provided array of fields from the rule or match.

``pagerduty_v2_payload_severity``: Sets the severity of the page. (defaults to `critical`, valid options: `critical`, `error`, `warning`, `info`)

``pagerduty_v2_payload_source``: Sets the source of the event, preferably the hostname or fqdn.

``pagerduty_v2_payload_source_args``: If set, and ``pagerduty_v2_payload_source`` is a formattable string, ElastAlert 2 will format the source based on the provided array of fields from the rule or match.

``pagerduty_v2_payload_custom_details``: List of keys:values to use as the content of the custom_details payload. Example - ip:clientip will map the value from the clientip index of Elasticsearch to JSON key named ip.

``pagerduty_v2_payload_include_all_info``: If True, this will include the entire Elasticsearch document as a custom detail field called "information" in the PagerDuty alert.

PagerTree
~~~~~~~~~

PagerTree alerter will trigger an incident to a predefined PagerTree integration url.

The alerter requires the following options:

``pagertree_integration_url``: URL generated by PagerTree for the integration.

``pagertree_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to PagerTree. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

Example usage::

    alert:
      - "pagertree"
    pagertree_integration_url: "PagerTree Integration URL"

Rocket.Chat
~~~~~~~~~~~

Rocket.Chat alerter will send a notification to a predefined channel. The body of the notification is formatted the same as with other alerters.
https://developer.rocket.chat/api/rest-api/methods/chat/postmessage

The alerter requires the following option:

``rocket_chat_webhook_url``: The webhook URL that includes your auth data and the ID of the channel (room) you want to post to. You can use a list of URLs to send to multiple channels.

Optional:

``rocket_chat_username_override``: By default Rocket.Chat will use username defined in Integration when posting to the channel. Use this option to change it (free text).

``rocket_chat_channel_override``: Incoming webhooks have a default channel, but it can be overridden. A public channel can be specified “#other-channel”, and a Direct Message with “@username”.

``rocket_chat_emoji_override``: By default ElastAlert 2 will use the :ghost: emoji when posting to the channel. You can use a different emoji per
ElastAlert 2 rule. Any Apple emoji can be used, see http://emojipedia.org/apple/ .

``rocket_chat_msg_color``: By default the alert will be posted with the ‘danger’ color. You can also use ‘good’ or ‘warning’ colors.

``rocket_chat_text_string``: Notification message you want to add.

``rocket_chat_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Rocket.Chat. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``rocket_chat_ca_certs``: Set this option to ``True`` if you want to validate the SSL certificate.

``rocket_chat_ignore_ssl_errors``: By default ElastAlert 2 will verify SSL certificate. Set this option to ``False`` if you want to ignore SSL errors.

``rocket_chat_timeout``: You can specify a timeout value, in seconds, for making communicating with Rocket.Chat. The default is 10. If a timeout occurs, the alert will be retried next time ElastAlert 2 cycles.

``rocket_chat_attach_kibana_discover_url``: Enables the attachment of the ``kibana_discover_url`` to the Rocket.Chat notification. The config ``generate_kibana_discover_url`` must also be ``True`` in order to generate the url. Defaults to ``False``.

``rocket_chat_kibana_discover_color``: The color of the Kibana Discover url attachment. Defaults to ``#ec4b98``.

``rocket_chat_kibana_discover_title``: The title of the Kibana Discover url attachment. Defaults to ``Discover in Kibana``.

Example rocket_chat_attach_kibana_discover_url, rocket_chat_kibana_discover_color, rocket_chat_kibana_discover_title::

    # (Required)
    generate_kibana_discover_url: True
    kibana_discover_app_url: "http://localhost:5601/app/discover#/"
    kibana_discover_index_pattern_id: "4babf380-c3b1-11eb-b616-1b59c2feec54"
    kibana_discover_version: "7.15"

    # (Optional)
    kibana_discover_from_timedelta:
      minutes: 10
    kibana_discover_to_timedelta:
      minutes: 10

    # (Required)
    rocket_chat_attach_kibana_discover_url: True

    # (Optional)
    rocket_chat_kibana_discover_color: "#ec4b98"
    rocket_chat_kibana_discover_title: "Discover in Kibana"

``rocket_chat_alert_fields``: You can add additional fields to your Rocket.Chat alerts using this field. Specify the title using `title` and a value for the field using `value`. Additionally you can specify whether or not this field should be a `short` field using `short: true`.

Example rocket_chat_alert_fields::

    rocket_chat_alert_fields:
      - title: Host
        value: monitor.host
        short: true
      - title: Status
        value: monitor.status
        short: true
      - title: Zone
        value: beat.name
        short: true

Squadcast
~~~~~~~~~

Alerts can be sent to Squadcast using the `http post` method described above and Squadcast will process it and send Phone, SMS, Email and Push notifications to the relevant person(s) and let them take actions.

Configuration variables in rules YAML file::

    alert: post
    http_post_url: <ElastAlert 2 Webhook URL copied from Squadcast dashboard>
    http_post_static_payload:
      Title: <Incident Title>
    http_post_all_values: true

For more details, you can refer the `Squadcast documentation <https://support.squadcast.com/docs/elastalert>`_.

ServiceNow
~~~~~~~~~~

The ServiceNow alerter will create a ne Incident in ServiceNow. The body of the notification is formatted the same as with other alerters.

The alerter requires the following options:

``servicenow_rest_url``: The ServiceNow RestApi url, this will look like https://developer.servicenow.com/dev.do#!/reference/api/orlando/rest/c_TableAPI#r_TableAPI-POST

``username``: The ServiceNow Username to access the api.

``password``: The ServiceNow password to access the api.

``short_description``: The ServiceNow password to access the api.

``comments``: Comments to be attached to the incident, this is the equivilant of work notes.

``assignment_group``: The group to assign the incident to.

``category``: The category to attach the incident to, use an existing category.

``subcategory``: The subcategory to attach the incident to, use an existing subcategory.

``cmdb_ci``: The configuration item to attach the incident to.

``caller_id``: The caller id (email address) of the user that created the incident (elastalert@somewhere.com).


Optional:

``servicenow_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to ServiceNow. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``servicenow_impact``: An integer 1, 2, or 3 representing high, medium, and low respectively. This measures the effect of an incident on business processes.

``servicenow_urgency``: An integer 1, 2, or 3 representing high, medium, and low respecitvely. This measures how long this incident can be delayed until there is a significant business impact.

Example usage::

    alert:
      - "servicenow"
    servicenow_rest_url: "servicenow rest url"
    username: "user"
    password: "password"
    short_description: "xxxxxx"
    comments: "xxxxxx"
    assignment_group: "xxxxxx"
    category: "xxxxxx"
    subcategory: "xxxxxx"
    cmdb_ci: "xxxxxx"
    caller_id: "xxxxxx"
    servicenow_impact: 1
    servicenow_urgenc: 3

Slack
~~~~~

Slack alerter will send a notification to a predefined Slack channel. The body of the notification is formatted the same as with other alerters.

The alerter requires the following option:

``slack_webhook_url``: The webhook URL that includes your auth data and the ID of the channel (room) you want to post to. Go to the Incoming Webhooks
section in your Slack account https://XXXXX.slack.com/services/new/incoming-webhook , choose the channel, click 'Add Incoming Webhooks Integration'
and copy the resulting URL. You can use a list of URLs to send to multiple channels.

Optional:

``slack_username_override``: By default Slack will use your username when posting to the channel. Use this option to change it (free text).

``slack_channel_override``: Incoming webhooks have a default channel, but it can be overridden. A public channel can be specified "#other-channel", and a Direct Message with "@username".

``slack_emoji_override``: By default ElastAlert 2 will use the ``:ghost:`` emoji when posting to the channel. You can use a different emoji per
ElastAlert 2 rule. Any Apple emoji can be used, see http://emojipedia.org/apple/ . If slack_icon_url_override parameter is provided, emoji is ignored.

``slack_icon_url_override``: By default ElastAlert 2 will use the ``:ghost:`` emoji when posting to the channel. You can provide icon_url to use custom image.
Provide absolute address of the pciture.

``slack_msg_color``: By default the alert will be posted with the 'danger' color. You can also use 'good' or 'warning' colors.

``slack_parse_override``: By default the notification message is escaped 'none'. You can also use 'full'.

``slack_text_string``: Notification message you want to add.

``slack_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Slack. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``slack_alert_fields``: You can add additional fields to your slack alerts using this field. Specify the title using `title` and a value for the field using `value`. Additionally you can specify whether or not this field should be a `short` field using `short: true`.

Example slack_alert_fields::

    slack_alert_fields:
      - title: Host
        value: monitor.host
        short: true
      - title: Status
        value: monitor.status
        short: true
      - title: Zone
        value: beat.name
        short: true

``slack_ignore_ssl_errors``: By default ElastAlert 2 will verify SSL certificate. Set this option to ``False`` if you want to ignore SSL errors.

``slack_title``: Sets a title for the message, this shows up as a blue text at the start of the message

``slack_title_link``: You can add a link in your Slack notification by setting this to a valid URL. Requires slack_title to be set.

``slack_timeout``: You can specify a timeout value, in seconds, for making communicating with Slack. The default is 10. If a timeout occurs, the alert will be retried next time ElastAlert 2 cycles.

``slack_attach_kibana_discover_url``: Enables the attachment of the ``kibana_discover_url`` to the slack notification. The config ``generate_kibana_discover_url`` must also be ``True`` in order to generate the url. Defaults to ``False``.

``slack_kibana_discover_color``: The color of the Kibana Discover url attachment. Defaults to ``#ec4b98``.

``slack_kibana_discover_title``: The title of the Kibana Discover url attachment. Defaults to ``Discover in Kibana``.

Example slack_attach_kibana_discover_url, slack_kibana_discover_color, slack_kibana_discover_title::

    # (Required)
    generate_kibana_discover_url: True
    kibana_discover_app_url: "http://localhost:5601/app/discover#/"
    kibana_discover_index_pattern_id: "4babf380-c3b1-11eb-b616-1b59c2feec54"
    kibana_discover_version: "7.15"

    # (Optional)
    kibana_discover_from_timedelta:
      minutes: 10
    kibana_discover_to_timedelta:
      minutes: 10

    # (Required)
    slack_attach_kibana_discover_url: True

    # (Optional)
    slack_kibana_discover_color: "#ec4b98"
    slack_kibana_discover_title: "Discover in Kibana"

``slack_ca_certs``: Set this option to ``True`` if you want to validate the SSL certificate.

``slack_footer``: Add a static footer text for alert. Defaults to "".

``slack_footer_icon``: A Public Url for a footer icon. Defaults to "".

``slack_image_url``: An optional URL to an image file (GIF, JPEG, PNG, BMP, or SVG). Defaults to "".

``slack_thumb_url``:  An optional URL to an image file (GIF, JPEG, PNG, BMP, or SVG) that is displayed as thumbnail. Defaults to "".

``slack_author_name``: An optional name used to identify the author. Defaults to "".

``slack_author_link``: An optional URL used to hyperlink the author_name. Defaults to "".

``slack_author_icon``: An optional URL used to display a 16x16 pixel icon beside the author_name. Defaults to "".

``slack_msg_pretext``: You can set the message attachment pretext using this option. Defaults to "".

``slack_attach_jira_ticket_url``: Add url to the jira ticket created. Only works if the Jira alert runs before Slack alert. Set the field to ``True`` in order to generate the url. Defaults to ``False``.

``slack_jira_ticket_color``: The color of the Jira Ticket url attachment. Defaults to ``#ec4b98``.

``slack_jira_ticket_title``: The title of the Jira Ticket url attachment. Defaults to ``Jira Ticket``.

Splunk On-Call (Formerly VictorOps)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Splunk On-Call (Formerly VictorOps) alerter will trigger an incident to a predefined Splunk On-Call (Formerly VictorOps) routing key. The body of the notification is formatted the same as with other alerters.

The alerter requires the following options:

``victorops_api_key``: API key generated under the 'REST Endpoint' in the Integrations settings.

``victorops_routing_key``: Splunk On-Call (Formerly VictorOps) routing key to route the alert to.

``victorops_message_type``: Splunk On-Call (Formerly VictorOps) field to specify severity level. Must be one of the following: INFO, WARNING, ACKNOWLEDGEMENT, CRITICAL, RECOVERY

Optional:

``victorops_entity_id``: The identity of the incident used by Splunk On-Call (Formerly VictorOps) to correlate incidents throughout the alert lifecycle. If not defined, Splunk On-Call (Formerly VictorOps) will assign a random string to each alert.

``victorops_entity_display_name``: Human-readable name of alerting entity to summarize incidents without affecting the life-cycle workflow. Will use ``alert_subject`` if not set.

``victorops_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Splunk On-Call (Formerly VictorOps). Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

Example usage::

    alert:
      - "victorops"
    victorops_api_key: "VictorOps API Key"
    victorops_routing_key: "VictorOps routing Key"
    victorops_message_type: "INFO"

Stomp
~~~~~

This alert type will use the STOMP protocol in order to push a message to a broker like ActiveMQ or RabbitMQ. The message body is a JSON string containing the alert details.
The default values will work with a pristine ActiveMQ installation.

The alerter requires the following options:

``stomp_hostname``: The STOMP host to use, defaults to ``localhost``.

``stomp_hostport``: The STOMP port to use, defaults to ``61613``.

``stomp_login``: The STOMP login to use, defaults to ``admin``.

``stomp_password``: The STOMP password to use, defaults to ``admin``.

Optional:

``stomp_ssl``: Connect the STOMP host using TLS, defaults to ``False``.

``stomp_destination``: The STOMP destination to use, defaults to ``/queue/ALERT``

The stomp_destination field depends on the broker, the /queue/ALERT example is the nomenclature used by ActiveMQ. Each broker has its own logic.

Example usage::

    alert:
      - "stomp"
    stomp_hostname: "localhost"
    stomp_hostport: "61613"
    stomp_login: "admin"
    stomp_password: "admin"
    stomp_destination: "/queue/ALERT"

Telegram
~~~~~~~~
Telegram alerter will send a notification to a predefined Telegram username or channel. The body of the notification is formatted the same as with other alerters.

The alerter requires the following two options:

``telegram_bot_token``: The token is a string along the lines of ``110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw`` that will be required to authorize the bot and send requests to the Bot API. You can learn about obtaining tokens and generating new ones in this document https://core.telegram.org/bots#6-botfather

``telegram_room_id``: Unique identifier for the target chat or username of the target channel using telegram chat_id (in the format "-xxxxxxxx")

Optional:

``telegram_api_url``: Custom domain to call Telegram Bot API. Default to api.telegram.org

``telegram_proxy``: By default ElastAlert 2 will not use a network proxy to send notifications to Telegram. Set this option using ``hostname:port`` if you need to use a proxy. only supports https.

``telegram_proxy_login``: The Telegram proxy auth username.

``telegram_proxy_pass``: The Telegram proxy auth password.

Example usage::

    alert:
      - "telegram"
    telegram_bot_token: "bot_token"
    telegram_room_id: "chat_id"


Tencent SMS
~~~~~~~~~~~

Required:

``tencent_sms_secret_id``: ``SecretID`` is used to identify the API caller.

``tencent_sms_secret_key``: ``SecretKey`` is used to encrypt the string to sign that can be verified on the server. You should keep it private and avoid disclosure.

``tencent_sms_sdk_appid``: SMS application ID, which is the `SdkAppId` generated after an application is added in the `SMS console <https://console.cloud.tencent.com/smsv2>`_, such as 1400006666

``tencent_sms_to_number``: Target mobile number in the E.164 standard (+[country/region code][mobile number])

Example: +8613711112222, which has a + sign followed by 86 (country/region code) and then by 13711112222 (mobile number). Up to 200 mobile numbers are supported

``tencent_sms_template_id``: Template ID. You must enter the ID of an approved template, which can be viewed in the `SMS console <https://console.cloud.tencent.com/smsv2>`_. 

If you need to send SMS messages to global mobile numbers, you can only use a Global SMS template.

Optional:

``tencent_sms_sign_name``: Content of the SMS signature, which should be encoded in UTF-8. You must enter an approved signature, such as Tencent Cloud. The signature information can be viewed in the SMS console.
Note: this parameter is required for Mainland China SMS.

``tencent_sms_region``: Region parameter, which is used to identify the region(`Mainland China <https://intl.cloud.tencent.com/document/api/382/40466#region-list>`_ or
`Global <https://cloud.tencent.com/document/api/382/52071#.E5.9C.B0.E5.9F.9F.E5.88.97.E8.A1.A8>`_) to which the data you want to work with belongs.

``tencent_sms_template_parm``: The number of template parameters needs to be consistent with the number of variables of the template corresponding to TemplateId.  
this value format by `rfc6901 <https://datatracker.ietf.org/doc/html/rfc6901>`_

.. code-block:: json

    {
      "_index" : "tmec"
      "_type" : "fluentd",
      "_id" : "PeXLrnsBvusb3d0w6dUl",
      "_score" : 1.0,
      "_source" : {
        "kubernetes" : {
          "host" : "9.134.191.187",
          "pod_id" : "66ba4e5a-1ad2-4655-9a8e-cffb6b942559",
          "labels" : {
            "release" : "nginx",
            "pod-template-hash" : "6bd96d6f74"
          },
          "namespace_name" : "app",
          "pod_name" : "app.nginx-6bd96d6f74-2ts4x"
        },
        "time" : "2021-09-04T03:13:24.192875Z",
        "message" : "2021-09-03T14:34:08+0000|INFO|vector eps : 192.168.0.2:10000,",
      }
    }


.. code-block:: yaml

    tencent_sms_template_id: "1123835"
    tencent_sms_template_parm:
      - "/kubernetes/pod_name"




TheHive
~~~~~~~

TheHive alerter can be used to create a new alert in TheHive. The alerter supports adding tags,
custom fields, and observables from the alert matches and rule data.

Required:

``hive_connection``: The connection details to your instance (see example below for the required syntax).
Only ``hive_apikey`` is required, ``hive_host`` and ``hive_port`` default to ``http://localhost`` and
``9000`` respectively.

``hive_alert_config``: Configuration options for the alert, see example below for structure.

If not supplied, the alert title and description will be populated from the ElastAlert 2 default
``title`` and ``alert_text`` fields, including any defined ``alert_text_args``.

Optional:

``tags`` can be populated from the matched record, using the same syntax used in ``alert_text_args``.
If a record doesn't contain the specified value, the rule itself will be examined for the tag. If
this doesn't contain the tag either, the tag is attached without modification to the alert. For
aggregated alerts, all matches are examined individually, and tags generated for each one. All tags
are then attached to the same alert.

``customFields`` can also be populated from rule fields as well as matched results. Custom fields
are only populated once. If an alert is an aggregated alert, the custom field values will be populated
using the first matched record, before checking the rule. If neither matches, the ``customField.value``
will be used directly.

``hive_observable_data_mapping``: If needed, matched data fields can be mapped to TheHive
observable types using the same syntax as ``tags``, described above. The algorithm used to populate
the observable value is also the same, including the behaviour for aggregated alerts.

``hive_proxies``: Proxy configuration.

``hive_verify``: Whether or not to enable SSL certificate validation. Defaults to False.

Example usage::

    alert: hivealerter

    hive_connection:
      hive_host: http://localhost
      hive_port: <hive_port>
      hive_apikey: <hive_apikey>
      hive_proxies:
        http: ''
        https: ''

    hive_alert_config:
      customFields:
        - name: example
          type: string
          value: example
      follow: True
      severity: 2
      status: 'New'
      source: 'elastalert'
      description: 'Sample description'
      tags: ['tag1', 'tag2']
      title: 'Title'
      tlp: 3
      type: 'external'

    hive_observable_data_mapping:
      - domain: agent.hostname
      - domain: response.domain
      - ip: client.ip

Twilio
~~~~~~

The Twilio alerter will send an alert to a mobile phone as an SMS from your Twilio
phone number. The SMS will contain the alert name. You may use either Twilio SMS
or Twilio Copilot to send the message, controlled by the ``twilio_use_copilot``
option.

Note that when Twilio Copilot *is* used the ``twilio_message_service_sid``
option is required. Likewise, when *not* using Twilio Copilot, the
``twilio_from_number`` option is required.

The alerter requires the following options:

``twilio_account_sid``: The SID of your Twilio account.

``twilio_auth_token``: Auth token associated with your Twilio account.

``twilio_to_number``: The phone number where you would like to send the alert.

Either one of
 * ``twilio_from_number``: The Twilio phone number from which the alert will be sent.
 * ``twilio_message_service_sid``: The SID of your Twilio message service.

Optional:

``twilio_use_copilot``: Whether or not to use Twilio Copilot, False by default.

Example with Copilot usage::

    alert:
      - "twilio"
    twilio_use_copilot: True
    twilio_to_number: "0123456789"
    twilio_auth_token: "abcdefghijklmnopqrstuvwxyz012345"
    twilio_account_sid: "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"
    twilio_message_service_sid: "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"

Example with SMS usage::

    alert:
      - "twilio"
    twilio_to_number: "0123456789"
    twilio_from_number: "9876543210"
    twilio_auth_token: "abcdefghijklmnopqrstuvwxyz012345"
    twilio_account_sid: "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"

Zabbix
~~~~~~

Zabbix will send notification to a Zabbix server. The item in the host specified receive a 1 value for each hit. For example, if the elastic query produce 3 hits in the last execution of ElastAlert 2, three '1' (integer) values will be send from elastalert to Zabbix Server. If the query have 0 hits, any value will be sent.

Required:

``zbx_sender_host``: The address where zabbix server is running, defaults to ``'localhost'``.

``zbx_sender_port``: The port where zabbix server is listenning, defaults to ``10051``.

``zbx_host``: This field setup the host in zabbix that receives the value sent by ElastAlert 2.

``zbx_key``: This field setup the key in the host that receives the value sent by ElastAlert 2.

Example usage::

    alert:
      - "zabbix"
    zbx_sender_host: "zabbix-server"
    zbx_sender_port: 10051
    zbx_host: "test001"
    zbx_key: "sender_load1"
