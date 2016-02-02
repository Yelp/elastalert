Rule Types and Configuration Options
************************************

Examples of several types of rule configuration can be found in the example_rules folder.

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
| ``name`` (string)                                            |           |
+--------------------------------------------------------------+           |
| ``type`` (string)                                            |           |
+--------------------------------------------------------------+           |
| ``alert`` (string or list)                                   |           |
+--------------------------------------------------------------+-----------+
| ``use_strftime_index`` (boolean, default False)              |  Optional |
+--------------------------------------------------------------+           |
| ``use_ssl`` (boolean, default False)                         |           |
+--------------------------------------------------------------+           |
| ``es_username`` (string, no default)                         |           |
+--------------------------------------------------------------+           |
| ``es_password`` (string, no default)                         |           |
+--------------------------------------------------------------+           |
| ``aggregation`` (time, no default)                           |           |
+--------------------------------------------------------------+           |
| ``description`` (string, default empty string)               |           |
+--------------------------------------------------------------+           |
| ``generate_kibana_link`` (boolean, default False)            |           |
+--------------------------------------------------------------+           |
|``use_kibana_dashboard`` (string, no default)                 |           |
+--------------------------------------------------------------+           |
|``kibana_url`` (string, default from es_host)                 |           |
+--------------------------------------------------------------+           |
|``use_kibana4_dashboard`` (string, no default)                |           |
+--------------------------------------------------------------+           |
|``kibana4_start_timedelta`` (time, default: 10 min)           |           |
+--------------------------------------------------------------+           |
|``kibana4_end_timedelta`` (time, default: 10 min)             |           |
+--------------------------------------------------------------+           |
|``use_local_time`` (boolean, default True)                    |           |
+--------------------------------------------------------------+           |
| ``realert`` (time, default: 1 min)                           |           |
+--------------------------------------------------------------+           |
|``exponential_realert`` (time, no default)                    |           |
+--------------------------------------------------------------+           |
|``match_enhancements`` (list of strs, no default)             |           |
+--------------------------------------------------------------+           |
| ``top_count_number`` (int, default 5)                        |           |
+--------------------------------------------------------------+           |
| ``top_count_keys`` (list of strs)                            |           |
+--------------------------------------------------------------+           |
|``raw_count_keys`` (boolean, default True)                    |           |
+--------------------------------------------------------------+           |
| ``include`` (list of strs, default ["*"])                    |           |
+--------------------------------------------------------------+           |
| ``filter`` (ES filter DSL, no default)                       |           |
+--------------------------------------------------------------+           |
| ``max_query_size`` (int, default global max_query_size)      |           |
+--------------------------------------------------------------+           |
| ``query_delay`` (time, default 0 min)                        |           |
+--------------------------------------------------------------+           |
| ``buffer_time`` (time, default from config.yaml)             |           |
|                                                              |           |
| IGNORED IF ``use_count_query`` or ``use_terms_query`` is true|           |
+--------------------------------------------------------------+           +
| ``timestamp_type`` (string, default iso)                     |           |
+--------------------------------------------------------------+           |
| ``_source_enabled`` (boolean, default True)                  |           |
+--------------------------------------------------------------+-----------+

|

+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|      RULE TYPE                                     | Any | Blacklist | Whitelist | Change | Frequency | Spike | Flatline |New_term|Cardinality|
+====================================================+=====+===========+===========+========+===========+=======+==========+========+===========+
| ``compare_key`` (string, no default)               |     |    Req    |  Req      |    Req |           |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``blacklist`` (list of strs, no default)            |     |   Req     |           |        |           |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``whitelist`` (list of strs, no default)            |     |           |   Req     |        |           |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``ignore_null`` (boolean, no default)              |     |           |   Req     |  Req   |           |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``query_key`` (string, no default)                 |     |           |           |   Req  |    Opt    |  Opt  |   Opt    |  Req   |  Opt      |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``timeframe`` (time, no default)                   |     |           |           |   Opt  |    Req    |  Req  |   Req    |        |  Req      |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``num_events`` (int, no default)                   |     |           |           |        |    Req    |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``attach_related`` (boolean, no default)           |     |           |           |        |    Opt    |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``use_count_query`` (boolean, no default)           |     |           |           |        |     Opt   | Opt   | Opt      |        |           |
|                                                    |     |           |           |        |           |       |          |        |           |
|``doc_type`` (string, no default)                   |     |           |           |        |           |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``use_terms_query`` (boolean, no default)           |     |           |           |        |     Opt   | Opt   |          | Opt    |           |
|                                                    |     |           |           |        |           |       |          |        |           |
|``doc_type`` (string, no default)                   |     |           |           |        |           |       |          |        |           |
|                                                    |     |           |           |        |           |       |          |        |           |
|``query_key`` (string, no default)                  |     |           |           |        |           |       |          |        |           |
|                                                    |     |           |           |        |           |       |          |        |           |
|``terms_size`` (int, default 50)                    |     |           |           |        |           |       |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
| ``spike_height`` (int, no default)                 |     |           |           |        |           |   Req |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``spike_type`` ([up|down|both], no default)         |     |           |           |        |           |   Req |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``alert_on_new_data`` (boolean, default False)      |     |           |           |        |           |   Opt |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``threshold_ref`` (int, no default)                 |     |           |           |        |           |   Opt |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``threshold_cur`` (int, no default)                 |     |           |           |        |           |   Opt |          |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``threshold`` (int, no default)                     |     |           |           |        |           |       |    Req   |        |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``fields`` (string, no default)                     |     |           |           |        |           |       |          | Req    |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``terms_window_size`` (time, default 30 days)       |     |           |           |        |           |       |          | Opt    |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``alert_on_missing_fields`` (boolean, default False)|     |           |           |        |           |       |          | Opt    |           |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``cardinality_field`` (string, no default)          |     |           |           |        |           |       |          |        |  Req      |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``max_cardinality`` (boolean, no default)           |     |           |           |        |           |       |          |        |  Opt      |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+
|``min_cardinality`` (boolean, no default)           |     |           |           |        |           |       |          |        |  Opt      |
+----------------------------------------------------+-----+-----------+-----------+--------+-----------+-------+----------+--------+-----------+

Common Configuration Options
============================

Every file that ends in ``.yaml`` in the ``rules_folder`` will be run by default.
The following configuration settings are common to all types of rules.

Required Settings
~~~~~~~~~~~~~~~~~

es_host
^^^^^^^

``es_host``: The hostname of the Elasticsearch cluster the rule will use to query. (Required, string, no default)

es_port
^^^^^^^

``es_port``: The port of the Elasticsearch cluster. (Required, number, no default)

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

use_ssl
^^^^^^^

``use_ssl``: Whether or not to connect to ``es_host`` using SSL. (Optional, boolean, default False)

es_username
^^^^^^^^^^^

``es_username``: basic-auth username for connecting to ``es_host``. (Optional, string, no default)

es_password
^^^^^^^^^^^

``es_password``: basic-auth password for connecting to ``es_host``. (Optional, string, no default)

es_url_prefix
^^^^^^^^^^^^^

``es_url_prefix``: URL prefix for the Elasticsearch endpoint. (Optional, string, no default)

use_strftime_index
^^^^^^^^^^^^^^^^^^

``use_strftime_index``: If this is true, ElastAlert will format the index using datetime.strftime for each query.
See https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior for more details.
If a query spans multiple days, the formatted indexes will be concatenated with commas. This is useful
as narrowing the number of indexes searched, compared to using a wildcard, may be significantly faster. For example, if ``index`` is
``logstash-%Y.%m.%d``, the query url will be similar to ``elasticsearch.example.com/logstash-2015.02.03/...`` or
``elasticsearch.example.com/logstash-2015.02.03,logstash-2015.02.04/...``.

aggregation
^^^^^^^^^^^

``aggregation``: This option allows you to aggregate multiple matches together into one alert. Every time a match is found,
ElastAlert will wait for the ``aggregation`` period, and send all of the matches that have occurred in that time for a particular
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

realert
^^^^^^^

``realert``: This option allows you to ignore repeating alerts for a period of time. If the rule uses a ``query_key``, this option
will be applied on a per key basis. All matches for a given rule, or for matches with the same ``query_key``, will be ignored for
the given time. All matches with a missing ``query_key`` will be grouped together using a value of ``_missing``.
This is applied to the time the alert is sent, not to the time of the event. It defaults to one minute, which means
that if ElastAlert is run over a large time period which triggers many matches, only the first alert will be sent by default. If you want
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

``query_delay``: This option will cause ElastAlert to subtract a time delta from every query, causing the rule to run with a delay.
This is useful if the data is Elasticsearch doesn't get indexed immediately. (Optional, time)

max_query_size
^^^^^^^^^^^^^^

``max_query_size``: The maximum number of documents that will be downloaded from Elasticsearch in a single query. If you
expect a large number of results, consider using ``use_count_query`` for the rule. If this
limit is reached, a warning will be logged but ElastAlert will continue without downloading more results. This setting will
override a global ``max_query_size``. (Optional, int, default value of global ``max_query_size``)

filter
^^^^^^

``filter``: A list of Elasticsearch query DSL filters that is used to query Elasticsearch. ElastAlert will query Elasticsearch using the format
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

``top_count_keys``: A list of fields. ElastAlert will perform a terms query for the top X most common values for each of the fields,
where X is 5 by default, or ``top_count_number`` if it exists.
For example, if ``num_events`` is 100, and ``top_count_keys`` is ``- "username"``, the alert will say how many of the 100 events
have each username, for the top 5 usernames. When this is computed, the time range used is from ``timeframe`` before the most recent event
to 10 minutes past the most recent event. Because ElastAlert uses an aggregation query to compute this, it will attempt to use the
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
If true, ElastAlert will generate a temporary Kibana dashboard and include a link to it in alerts. The dashboard
consists of an events over time graph and a table with ``include`` fields selected in the table. If the rule uses ``query_key``, the
dashboard will also contain a filter for the ``query_key`` of the alert. The dashboard schema will
be uploaded to the kibana-int index as a temporary dashboard. (Optional, boolean, default False)

kibana_url
^^^^^^^^^^

``kibana_url``: The url to access Kibana. This will be used if ``generate_kibana_link`` or
``use_kibana_dashboard`` is true. If not specified, a URL will be constructed using ``es_host`` and ``es_port``.
(Optional, string, default ``http://<es_host>:<es_port>/_plugin/kibana/``)

use_kibana_dashboard
^^^^^^^^^^^^^^^^^^^^

``use_kibana_dashboard``: The name of a Kibana 3 dashboard to link to. Instead of generating a dashboard from a template,
ElastAlert can use an existing dashboard. It will set the time range on the dashboard to around the match time,
upload it as a temporary dashboard, add a filter to the ``query_key`` of the alert if applicable,
and put the url to the dashboard in the alert. (Optional, string, no default)

use_kibana4_dashboard
^^^^^^^^^^^^^^^^^^^^^

``use_kibana4_dashboard``: A link to a Kibana 4 dashboard. For example, "https://kibana.example.com/#/dashboard/My-Dashboard".
This will set the time setting on the dashboard from the match time minus the timeframe, to 10 minutes after the match time.
Note that this does not support filtering by ``query_key`` like Kibana 3.

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

use_local_time
^^^^^^^^^^^^^^

``use_local_time``: Whether to convert timestamps to the local time zone in alerts. If false, timestamps will
be converted to UTC, which is what ElastAlert uses internally. (Optional, boolean, default true)

match_enhancements
^^^^^^^^^^^^^^^^^^

``match_enhancements``: A list of enhancement modules to use with this rule. An enhancement module is a subclass of enhancements.BaseEnhancement
that will be given the match dictionary and can modify it before it is passed to the alerter. The enhancements should be specified as
``module.file.EnhancementName``. See :ref:`Enhancements` for more information. (Optional, list of strings, no default)

query_key
^^^^^^^^^

``query_key``: Having a query key means that realert time will be counted separately for each unique value of ``query_key``. For rule types which
count documents, such as spike, frequency and flatline, it also means that these counts will be independent for each unique value of ``query_key``.
For example, if ``query_key`` is set to ``username`` and ``realert`` is set, and an alert triggers on a document with ``{'username': 'bob'}``,
additional alerts for ``{'username': 'bob'}`` will be ignored while other usernames will trigger alerts. Documents which are missing the
``query_key`` will be grouped together. A list of fields may also be used, which will create a compound query key. This compound key is
treated as if it were a single field whose value is the component values, or "None", joined by commas. A new field with the key
"field1,field2,etc" will be created in each document and may conflict with existing fields of the same name.

timestamp_type
^^^^^^^^^^^^^^

``timestamp_type``: One of ``iso``, ``unix``, or ``unix_ms``. This option will set the type of ``@timestamp`` (or ``timestamp_field``) used
to query Elasticsearch. ``iso`` will use ISO8601 timestamps, which will work with any Elasticsearch date type field. ``unix`` will
query using an integer unix (seconds since 1/1/1970) timestamp. ``unix_ms`` will use milliseconds unix timestamp. The default is ``iso``.
(Optional, string enum, default iso).

_source_enabled
^^^^^^^^^^^^^^^

``_source_enabled``: If true, ElastAlert will use _source to retrieve fields from documents in Elasticsearch. If false,
ElastAlert will use ``fields`` to retrieve stored fields. Both of these are represented internally as if they came from ``_source``.
See https://www.elastic.co/guide/en/elasticsearch/reference/1.3/mapping-fields.html for more details. The fields used come from ``include``,
see above for more details. (Optional, boolean, default True)

Some rules and alerts require additional options, which also go in the top level of the rule configuration file.


.. _testing :

Testing Your Rule
====================

Once you've written a rule configuration, you will want to validate it. To do so, you can either run ElastAlert in debug mode,
or use ``elastalert-test-rule``, which is a script that makes various aspects of testing easier.

It can:

- Check that the configuration file loaded successfully.

- Check that the Elasticsearch filter parses.

- Run against the last X day(s) and the show the number of hits that match your filter.

- Show the available terms in one of the results.

- Save documents returned to a JSON file.

- Run ElastAlert using either a JSON file or actual results from Elasticsearch.

- Print out debug alerts or trigger real alerts.

- Check that, if they exist, the primary_key, compare_key and include terms are in the results.

- Show what metadata documents would be written to ``elastalert_status``.

Without any optional arguments, it will run ElastAlert over the last 24 hours and print out any alerts that would have occurred.
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

``--count-only``: Only find the number of matching documents and list available fields. ElastAlert will not be run and documents will not be downloaded.

``--days N``: Instead of the default 1 day, query N days. For selecting more specific time ranges, you must run ElastAlert itself and use ``--start``
and ``--end``.

``--save-json FILE``: Save all documents downloaded to a file as JSON. This is useful if you wish to modify data while testing or do offline
testing in conjunction with ``--data FILE``. A maximum of 10,000 documents will be downloaded.

``--data FILE``: Use a JSON file as a data source instead of Elasticsearch. The file should be a single list containing objects,
rather than objects on separate lines. Note than this uses mock functions which mimic some Elasticsearch query methods and is not
guarenteed to have the exact same results as with Elasticsearch. For example, analyzed string fields may behave differently.

``--alert``: Trigger real alerts instead of the debug (logging text) alert.

.. note::
   Results from running this script may not always be the same as if an actual ElastAlert instance was running. Some rule types, such as spike
   and flatline require a minimum elapsed time before they begin alerting, based on their timeframe. In addition, use_count_query and
   use_terms_query rely on run_every to determine their resolution. This script uses a fixed 5 minute window, which is the same as the default.


.. _ruletypes:

Rule Types
===========

The various ``RuleType`` classes, defined in ``elastalert/ruletypes.py``, form the main logic behind ElastAlert. An instance
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

``blacklist``: A list of blacklisted values. The ``compare_key`` term must be equal to one of these values for it to match.

Whitelist
~~~~~~~~~

``whitelist``: Similar to ``blacklist``, this rule will compare a certain field to a whitelist, and match if the list does not contain
the term.

This rule requires three additional options:

``compare_key``: The name of the field to use to compare to the whitelist.

``ignore_null``: If true, events without a ``compare_key`` field will not match.

``whitelist``: A list of whitelisted values. The ``compare_key`` term must be in this list or else it will match.

Change
~~~~~~

For an example configuration file using this rule type, look at ``example_rules/example_change.yaml``.

``change``: This rule will monitor a certain field and match if that field changes. The field
must change with respect to the last event with the same ``query_key``.

This rule requires three additional options:

``compare_key``: The name of the field to monitor for changes.

``ignore_null``: If true, events without a ``compare_key`` field will not count as changed.

``query_key``: This rule is applied on a per-``query_key`` basis. This field must be present in all of
the events that are checked.

There is also an optional field:

``timeframe``: The maximum time between changes. After this time period, ElastAlert will forget the old value
of the ``compare_key`` field.

Frequency
~~~~~~~~~

For an example configuration file using this rule type, look at ``example_rules/example_frequency.yaml``.

``frequency``: This rule matches when there are at least a certain number of events in a given time frame. This
may be counted on a per-``query_key`` basis.

This rule requires two additional options:

``num_events``: The number of events which will trigger an alert.

``timeframe``: The time that ``num_events`` must occur within.

Optional:

``use_count_query``: If true, ElastAlert will poll elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. ``doc_type`` must be set to use this.

``doc_type``: Specify the ``_type`` of document to search for. This must be present if ``use_count_query`` or ``use_terms_query`` is set.

``use_terms_query``: If true, ElastAlert will make an aggregation query against Elasticsearch to get counts of documents matching
each unique value of ``query_key``. This must be used with ``query_key`` and ``doc_type``. This will only return a maximum of ``terms_size``,
default 50, unique terms.

``terms_size``: When used with ``use_terms_query``, this is the maximum number of terms returned per query. Default is 50.

``query_key``: Counts of documents will be stored independently for each value of ``query_key``. Only ``num_events`` documents,
all with the same value of ``query_key``, will trigger an alert.


``attach_related``: Will attach all the related events to the event that triggered the frequency alert. For example in an alert triggered with ``num_events``: 3,
the 3rd event will trigger the alert on itself and add the other 2 events in a key named ``related_events`` that can be accessed in the alerter.

Spike
~~~~~~

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

``threshold_ref``: The minimum number of events that must exist in the reference window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_ref: 10``, than the 'reference' window must contain at least 10 events and the 'current' window at
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
    hour1: 20 events (ref: 0, cur: 20) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour2: 100 events (ref: 0, cur: 120) - No alert because (a) threshold_ref not met, (b) ref window not filled
    hour3: 100 events (ref: 20, cur: 200) - Alert because (a) spike_height met, (b) threshold_ref met, (c) ref window filled

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

``use_count_query``: If true, ElastAlert will poll elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. ``doc_type`` must be set to use this.

``doc_type``: Specify the ``_type`` of document to search for. This must be present if ``use_count_query`` or ``use_terms_query`` is set.

``use_terms_query``: If true, ElastAlert will make an aggregation query against Elasticsearch to get counts of documents matching
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

``use_count_query``: If true, ElastAlert will poll Elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. ``doc_type`` must be set to use this.

``doc_type``: Specify the ``_type`` of document to search for. This must be present if ``use_count_query`` or ``use_terms_query`` is set.

``use_terms_query``: If true, ElastAlert will make an aggregation query against Elasticsearch to get counts of documents matching
each unique value of ``query_key``. This must be used with ``query_key`` and ``doc_type``. This will only return a maximum of ``terms_size``,
default 50, unique terms.

``terms_size``: When used with ``use_terms_query``, this is the maximum number of terms returned per query. Default is 50.

``query_key``: With flatline rule, ``query_key`` means that an alert will be triggered if any value of ``query_key`` has been seen at least once
and then falls below the threshold.

New Term
~~~~~~~~

``new_term``: This rule matches when a new value appears in a field that has never been seen before. When ElastAlert starts, it will
use an aggregation query to gather all known terms for a list of fields.

This rule requires one additional option:

``fields``: A list of fields to monitor for new terms. ``query_key`` will be used if ``fields`` is not set.

Optional:

``terms_window_size``: The amount of time used for the initial query to find existing terms. No term that has occurred within this time frame
will trigger an alert. The default is 30 days.

``alert_on_missing_field``: Whether or not to alert when a field is missing from a document. The default is false.

``use_terms_query``: If true, ElastAlert will use aggregation queries to get terms instead of regular search queries. This is faster
than regular searching if there is a large number of documents. If this is used, you may only specify a single field, and must also set
``query_key`` to that field. Also, note that ``terms_size`` (the number of buckets returned per query) defaults to 50. This means
that if a new term appears but there are at least 50 terms which appear more frequently, it will not be found.

Cardinality
~~~~~~~~

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


.. _alerts:

Alerts
========

Each rule may have any number of alerts attached to it. Alerts are subclasses of ``Alerter`` and are passed
a dictionary, or list of dictionaries, from ElastAlert which contain relevant information. They are configured
in the rule configuration file similarly to rule types.

To set the alerts for a rule, set the ``alert`` option to the name of the alert, or a list of the names of alerts:

``alert: email``

or

.. code-block:: yaml

    alert:
    - email
    - jira

E-mail subject or JIRA issue summary can also be customized by adding an ``alert_subject`` that contains a custom summary.
It can be further formatted using standard Python formatting syntax::

    alert_subject: "Issue {0} occurred at {1}"

The arguments for the formatter will be fed from the matched objects related to the alert.
The field names whose values will be used as the arguments can be passed with ``alert_subject_args``::


    alert_subject_args:
    - issue.name
    - "@timestamp"

It is mandatory to enclose the ``@timestamp`` field in quotes since in YAML format a token cannot begin with the ``@`` character. Not using the quotation marks will trigger a YAML parse error.

In case the rule matches multiple objects in the index, only the first match is used to populate the arguments for the formatter.

If the field(s) mentioned in the arguments list are missing, the email alert will have the text ``<MISSING VALUE>`` in place of its expected value.

Alert Content
~~~~~~~~~~~~~~~

There are several ways to format the body text of the various types of events. In EBNF::

    rule_name           = name
    alert_text          = alert_text
    ruletype_text       = Depends on type
    top_counts_header   = top_count_key, ":"
    top_counts_value    = Value, ": ", Count
    top_counts          = top_counts_header, LF, top_counts_value
    field_values        = Field, ": ", Value

Similarly to ``alert_subject``, ``alert_text`` can be further formatted using standard Python formatting syntax.
The field names whose values will be used as the arguments can be passed with ``alert_text_args``.

By default::

    body                = rule_name

                          [alert_text]

                          ruletype_text

                          {top_counts}

                          {field_values}

With ``alert_text_type: alert_text_only``::

    body                = rule_name

                          alert_text

With ``alert_text_type: exclude_fields``::

    body                = rule_name

                          [alert_text]

                          ruletype_text

                          {top_counts}

ruletype_text is the string returned by RuleType.get_match_str.

field_values will contain every key value pair included in the results from Elasticsearch. These fields include "@timestamp" (or the value of ``timestamp_field``),
every key in ``included``, every key in ``top_count_keys``, ``query_key``, and ``compare_key``. If the alert spans multiple events, these values may
come from an individual event, usually the one which triggers the alert.

Command
~~~~~~~

The command alert allows you to execute an arbitrary command and pass arguments or stdin from the match. Arguments to the command can use
Python format string syntax to access parts of the match. The alerter will open a subprocess and optionally pass the match, or matches
in the case of an aggregated alert, as a JSON array, to the stdin of the process.

This alert requires one option:

``command``: A list of arguments to execute or a string to execute. If in list format, the first argument is the name of the program to execute. If passing a
string, the command will be executed through the shell. The command string or args will be formatted using Python's % string format syntax with the
match passed the format argument. This means that a field can be accessed with ``%(field_name)s``. In an aggregated alert, these fields will come
from the first match.

Optional:

``pipe_match_json``: If true, the match will be converted to JSON and passed to stdin of the command. Note that this will cause ElastAlert to block
until the command exits or sends an EOF to stdout.

Example usage::

    alert:
      - command
    command: ["/bin/send_alert", "--username", "%(username)s"]

.. warning::

    Executing commmands with untrusted data can make it vulnerable to shell injection! If you use formatted data in
    your command, it is highly recommended that you use a args list format instead of a shell string.


Email
~~~~~

This alert will send an email. It connects to an smtp server located at ``smtp_host``, or localhost by default.
If available, it will use STARTTLS.

This alert requires one additional option:

``email``: An address or list of addresses to sent the alert to.

Optional:

``smtp_host``: The SMTP host to use, defaults to localhost.

``smtp_port``: The port to use. Default is 25.

``smtp_ssl``: Connect the SMTP host using SSL, defaults to ``false``. If ``smtp_ssl`` is not used, ElastAlert will still attempt
STARTTLS.

``smtp_auth_file``: The path to a file which contains SMTP authentication credentials. It should be YAML formatted and contain
two fields, ``user`` and ``password``. If this is not present, no authentication will be attempted.

``email_reply_to``: This sets the Reply-To header in the email. By default, the from address is ElastAlert@ and the domain will be set
by the smtp server.

``from_addr``: This sets the From header in the email. By default, the from address is ElastAlert@ and the domain will be set
by the smtp server.

``cc``: This adds the CC emails to the list of recipients. By default, this is left empty.

``bcc``: This adds the BCC emails to the list of recipients but does not show up in the email message. By default, this is left empty.

Jira
~~~~~

The JIRA alerter will open a ticket on jira whenever an alert is triggered. You must have a service account for ElastAlert to connect with.
The credentials of the service account are loaded from a separate file. The ticket number will be written to the alert pipeline, and if it
is followed by an email alerter, a link will be included in the email.

This alert requires four additional options:

``jira_server``: The hostname of the JIRA server.

``jira_project``: The project to open the ticket under.

``jira_issuetype``: The type of issue that the ticket will be filed as. Note that this is case sensitive.

``jira_account_file``: The path to the file which contains JIRA account credentials.

For an example JIRA account file, see ``example_rules/jira_acct.yaml``. The account file is also yaml formatted and must contain two fields:

``user``: The username.

``password``: The password.

Optional:

``jira_component``: The name of the component to set the ticket to.

``jira_description``: Similar to ``alert_text``, this text is prepended to the JIRA description.

``jira_label``: The label to add to the JIRA ticket.

``jira_priority``: The index of the priority to set the issue to. In the JIRA dropdown for priorities, 0 would represent the first priority,
1 the 2nd, etc.

``jira_bump_tickets``: If true, ElastAlert search for existing tickets newer than ``jira_max_age`` and comment on the ticket with
information about the alert instead of opening another ticket. ElastAlert finds the existing ticket by searching by summary. If the
summary has changed or contains special characters, it may fail to find the ticket. If you are using a custom ``alert_subject``,
the two summaries must be exact matches. Defaults to false.

``jira_max_age``: If ``jira_bump_tickets`` is true, the maximum age of a ticket, in days, such that ElastAlert will comment on the ticket
instead of opening a new one. Default is 30 days.

``jira_bump_not_in_statuses``: If ``jira_bump_tickets`` is true, a list of statuses the ticket must **not** be in for ElastAlert to comment on
the ticket instead of opening a new one. For example, to prevent comments being added to resolved or closed tickets, set this to 'Resolved'
and 'Closed'. This option should not be set if the ``jira_bump_in_statuses`` option is set.

Example usage::

    jira_bump_not_in_statuses:
      - Resolved
      - Closed

``jira_bump_in_statuses``: If ``jira_bump_tickets`` is true, a list of statuses the ticket *must be in* for ElastAlert to comment on
the ticket instead of opening a new one. For example, to only comment on 'Open' tickets  -- and thus not 'In Progress', 'Analyzing',
'Resolved', etc. tickets -- set this to 'Open'. This option should not be set if the ``jira_bump_not_in_statuses`` option is set.

Example usage::

    jira_bump_in_statuses:
      - Open

OpsGenie
~~~~~~~~

OpsGenie alerter will create an alert which can be used to notify Operations people of issues or log information. An OpsGenie ``API``
integration must be created in order to acquire the necessary ``opsgenie_key`` rule variable. Currently the OpsGenieAlerter only creates
an alert, however it could be extended to update or close existing alerts.

It is necessary for the user to create an OpsGenie Rest HTTPS API `integration page <https://app.opsgenie.com/integration>`_ in order to create alerts.

The OpsGenie alert requires one option:

``opsgenie_key``: The randomly generated API Integration key created by OpsGenie.

Optional:

``opsgenie_account``: The OpsGenie account to integrate with.

``opsgenie_recipients``: A list OpsGenie recipients who will be notified by the alert.

``opsgenie_teams``: A list of OpsGenie teams to notify (useful for schedules with escalation).

``opsgenie_tags``: A list of tags for this alert.

SNS
~~~

The SNS alerter will send an SNS notification. The body of the notification is formatted the same as with other alerters. The SNS alerter
uses boto and can use credentials in the rule yaml or in a standard boto credential file.
See http://boto.readthedocs.org/en/latest/boto_config_tut.html#details for details.

SNS requires one option:

``sns_topic_arn``: The SNS topic's ARN. For example, ``arn:aws:sns:us-east-1:123456789:somesnstopic``

Optional:

``aws_access_key``: An access key to connect to SNS with.

``aws_secret_key``: The secret key associated with the access key.

``aws_region``: The AWS region in which the SNS resource is located. Default is us-east-1

HipChat
~~~~~~~

HipChat alerter will send a notification to a predefined HipChat room. The body of the notification is formatted the same as with other alerters.

The alerter requires the following two options:

``hipchat_auth_token``: The randomly generated notification token created by HipChat. Go to https://XXXXX.hipchat.com/account/api and use
'Create new token' section, choosing 'Send notification' in Scopes list.

``hipchat_room_id``: The id associated with the HipChat room you want to send the alert to. Go to https://XXXXX.hipchat.com/rooms and choose
the room you want to post to. The room ID will be the numeric part of the URL.

``hipchat_domain``: The custom domain in case you have Hipchat own server deployment. Default is api.hipchat.com.

``hipchat_ignore_ssl_errors``: Ignore SSL errors (self-signed certificates, etc.). Default is false.

Slack
~~~~~

Slack alerter will send a notification to a predefined Slack channel. The body of the notification is formatted the same as with other alerters.

The alerter requires the following option:

``slack_webhook_url``: The webhook URL that includes your auth data and the ID of the channel (room) you want to post to. Go to the Incoming Webhooks
section in your Slack account https://XXXXX.slack.com/services/new/incoming-webhook , choose the channel, click 'Add Incoming Webhooks Integration'
and copy the resulting URL.

Optional:

``slack_username_override``: By default Slack will use your username when posting to the channel. Use this option to change it (free text).

``slack_emoji_override``: By default Elastalert will use the :ghost: emoji when posting to the channel. You can use a different emoji per
Elastalert rule. Any Apple emoji can be used, see http://emojipedia.org/apple/

``slack_msg_color``: By default the alert will be posted with the 'danger' color. You can also use 'good' or 'warning' colors.

``slack_proxy``: By default Elastalert will not use a network proxy to send notifications to Slack. Set this option using ``hostname:port`` if you need to use a proxy.

PagerDuty
~~~~~~~~~

PagerDuty alerter will trigger an incident to a predefined PagerDuty service. The body of the notification is formatted the same as with other alerters.

The alerter requires the following option:

``pagerduty_service_key``: Integration Key generated after creating a service with the 'Use our API directly' option at Integration Settings

``pagerduty_client_name``: The name of the monitoring client that is triggering this event.

VictorOps  
~~~~~~~~~

VictorOps alerter will trigger an incident to a predefined VictorOps routing key. The body of the notification is formatted the same as with other alerters.

The alerter requires the following options:

``victorops_api_key``: API key generated under the 'REST Endpoint' in the Integrations settings.

``victorops_routing_key``: VictorOps routing key to route the alert to.

``victorops_message_type``: VictorOps field to specify serverity level. Must be one of the following: INFO, WARNING, ACKNOWLEDGEMENT, CRITICAL, RECOVERY

Optional:

``victorops_entity_display_name``: Humna-readable name of alerting entity. Used by VictorOps to correlate incidents by host througout the alert lifecycle. 

Debug
~~~~~~

The debug alerter will log the alert information using the Python logger at the info level. It is logged into a Python Logger object with the name ``elastalert`` that can be easily accessed using the ``getLogger`` command.
