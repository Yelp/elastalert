Rule types and configuration options
************************************

Examples of several types of rule configuration can be found in the example_rules folder.

.. _commonconfig:

Common configuration options
============================

Every file that ends in ``.yaml`` in the ``rules_folder`` will be run by default.
The following configuration settings are common to all types of rules:

Required settings
~~~~~~~~~~~~~~~~~

``es_host``: The hostname of the Elasticsearch cluster the rule will use to query. (Required, string, no default)

``es_port``: The port of the Elasticsearch cluster. (Required, number, no default)

``index``: The name of the index that will be searched. Wildcards can be used here, such as: 
``index: my-index-*`` which will match ``my-index-2014-10-05``. You can also use a format string containing
``%Y`` for year, ``%m`` for month, and ``%d`` for day. To use this, you must also set ``use_strftime_index`` to true. (Required, string, no default)

``use_strftime_index``: If this is true, ElastAlert will format the index using datetime.strftime for each query.
See https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior for more details.
If a query spans multiple days, the formatted indexes will be concatenated with commas. This is useful
as narrowing the number of indexes searched, compared to using a wildcard, may be significantly faster. For example, if ``index`` is
``logstash-%Y.%m.%d``, the query url will be similar to ``elasticsearch.example.com/logstash-2015.02.03/...`` or
``elasticsearch.example.com/logstash-2015.02.03,logstash-2015.02.04/...``.

``name``: The name of the rule. This must be unique across all rules. The name will be used in
alerts and used as a key when writing and reading search metadata back from Elasticsearch. (Required, string, no default)

``type``: The ``RuleType`` to use. This may either be one of the built in rule types, see :ref:`Rule Types <ruletypes>` section below for more information,
or loaded from a module. For loading from a module, the type should be specified as ``module.file.RuleName``. (Required, string, no default)

``alert``: The ``Alerter`` type to use. This may be one of the built in alerts, see :ref:`Alert Types <alerts>` section below for more information,
or loaded from a module. For loading from a module, the alert should be specified as ``module.file.AlertName``. (Required, string, no default)

Optional settings
~~~~~~~~~~~~~~~~~

``aggregation``: This option allows you to aggregate multiple matches together into one alert. Every time a match is found,
ElastAlert will wait for the ``aggregation`` period, and send all of the matches that have occurred in that time for a particular 
rule together. For example, 

``aggregation: hours: 2``

means that if one match occurred at 12:00, another at 1:00, and a third at 2:30, one
alert would be sent at 2:00, containing the first two matches, and another at 4:30, containing the third match plus any additional matches
occurring before 4:30. This can be very useful if you expect a large number of matches and only want a periodic report. (Optional, time, default none)

``realert``: This option allows you to ignore repeat alerts for a period of time. If the rule uses a ``query_key``, this option
will be applied on a per key basis. All matches for a given rule, or for matches with the same ``query_key``, will be ignored for
the given time. This is applied to the time the alert is sent, not to the time of the event. It defaults to one minute, which means
that if ElastAlert is run over a large time period which triggers many matches, only the first alert will be sent by default. If you want
every alert, set realert to 0 minutes. (Optional, time, default 1 minute)

``buffer_time``: This options allows the rule to override the ``buffer_time`` global setting defined in config.yaml. (Optional, time)

``max_query_size``: The maximum number of documents that will be downloaded from Elasticsearch in a single query. If you
expect a large number of results, consider using ``use_count_query`` for the rule. If this
limit is reached, a warning will be logged but ElastAlert will continue without downloading more results. This setting will
override a global ``max_query_size``. (Optional, int, default 100,000)

``filter``: A list of Elasticsearch query DSL filters that is used to query Elasticsearch. ElastAlert will query Elasticsearch using the format
``{'filtered': {'and': [config.filter]}}`` with an additional timestamp range filter. 
All of the results of querying with these filters are passed to the ``RuleType`` for analysis. 
For more information writing filters, see :ref:`Writing Filters <writingfilters>`. (Required, Elasticsearch query DSL, no default)

``include``: A list of terms that should be included in query results and passed to rule types and alerts. '@timestamp', ``query_key``,
``compare_key``, and ``top_count_keys``  are automatically included, if present. (Optional, list of strings)

``generate_kibana_link``: If true, ElastAlert will generate a temporary Kibana dashboard and include a link to it in alerts. The dashboard
consists of an events over time graph and a table with ``include`` fields selected in the table. If the rule uses ``query_key``, the
dashboard will also contain a filter for the ``query_key`` of the alert. The dashboard schema will
be uploaded to the kibana-int index as a temporary dashboard. (Optional, boolean, default False)

``kibana_url``: The url to access the kibana plugin. This will be used if ``generate_kibana_link`` is true. 
(Optional, string, default ``http://<es_host>:<es_port>/_plugin/kibana/``)

``use_kibana_dashboard``: The name of a dashboard to link to. Instead of generating a dashboard from a template, 
ElastAlert can use an existing dashboard. It will set the time range on the dashboard to around the match time,
upload it as a temporary dashboard, add a filter to the ``query_key`` of the alert if applicable,
and put the url to the dashboard in the alert. (Optional, string, no default)

``use_local_time``: Whether to convert timestamps to the local time zone in alerts. If false, timestamps will
be converted to UTC, which is what ElastAlert uses internally. (Optional, boolean, default true)

``match_enhancements``: A list of enhancement modules to use with this rule. An enhancement module is a subclass of enhancements.BaseEnhancement
that will be given the match dictionary and can modify it before it is passed to the alerter. The enhancements should be specified as 
``module.file.EnhancementName``. See :ref:`Enhancements` for more information. (Optional, list of strings, no default)

Some rules and alerts require additional options, which also go in the top level of the rule configuration file.

Testing if your rule is valid
==============================

Once you've written a rule configuration, you will want to validate it. To do so, use ``elastalert-test-rule``.

This will:

- Check that the configuration file loaded successfully.

- Check that the Elasticsearch filter parses.

- Run against the last day and the show the number of hits that match your filter.

- Show the available terms in one of the results.

- Check that, if they exist, the primary_key, compare_key and include terms are in the results.

This tool does NOT test whether an alert would be triggered.

.. code-block:: console

    $ elastalert-test-rule my_rules/rule1.yaml my_rules/rule2.yaml
    Loaded Example rule1
    Got 100+ hits from the last 1 day
    Available terms in first hit:
        @timestamp
        field1
        field2
        ...
    Included term this_field_doesnt_exist may be missing or null

    Loaded Other rule2
    Got 2 hits from the last 1 day
    Available terms in first hit:
        @timestamp
        field1
        field2
        ....

Optionally, you may pass --days N to query the last N days, instead of the default 1 day.


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

``query_key``: The number of events is remembered separately for each unique ``query_key`` field. If this option
is set, the field must be present for all events.

``top_count_keys``: A list of fields. ElastAlert will tell you the count for the top X most common values for each of the fields,
where X is 5 by default, or ``top_count_number`` if it exists.
For example, if ``num_events`` is 100, and ``top_count_keys`` is ``- "username"``, the alert will say how many of the 100 events
have each username, for the top 5 usernames.

``top_count_number``: The number of terms to list if ``top_count_keys`` is set.

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
before a baseline rate has been established. This can be overridden using ``alert_on_new_events``.


Optional:

``threshold_ref``: The minimum number of events that must exist in the reference window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_ref: 10``, than the 'reference' window must contain at least 10 events and the 'current' window at
least three times that for an alert to be triggered.

``threshold_cur``: The minimum number of events that must exist in the current window for an alert to trigger. For example, if
``spike_height: 3`` and ``threshold_cur: 60``, then an alert will occur if the current window has more than 60 events and
the reference window has less than a third as many.

To illustrate the use of ``threshold_ref``, ``threshold_cur``, ``alert_on_new_events``, ``timeframe`` and ``spike_height`` together,
consider the following examples::

    " Alert if at least 15 events occur within two hours and less than a quarter of that number occured within the previous two hours. "
    timeframe: hours: 2
    spike_height: 4
    threshold_cur: 15

    hour1: 5 events (ref: 0, cur: 5) - No alert because threshold_cur not met
    hour2: 5 events (ref: 0, cur: 10) - No alert because threshold_cur not met
    hour3: 10 events (ref: 5, cur: 15) - No alert because spike_height not met
    hour4: 35 events (ref: 10, cur: 45) - Alert because spike_height and threshold_cur met

    hour1: 20 events (ref: 0, cur: 20) - No alert because ref window not filled
    hour2: 21 events (ref: 0, cur: 41) - No alert because ref window not filled
    hour3: 19 events (ref: 20, cur: 40) - No alert because spike_height not met
    hour4: 23 events (ref: 41, cur: 42) - No alert because spike_height not met

    hour1: 10 events (ref: 0, cur: 10) - No alert because threshold_cur not met
    hour2: 0 events (ref: 0, cur: 10) - No alert because threshold_cur not met
    hour3: 0 events (ref: 10, cur: 0) - No alert because spike_height not met
    hour4: 30 events (ref: 10, cur: 30) - No alert because spike_height not met
    hour5: 5 events (ref: 0, cur: 35) - Alert because threshold_cur and spike_height met

    " Alert if at least 5 events occur within two hours, and twice as many events occur within the next two hours. "
    timeframe: hours: 2
    spike_height: 2
    threshold_ref: 5

    hour1: 20 events (ref: 0, cur: 20) - No alert because threshold_ref not met
    hour2: 100 events (ref: 0, cur: 120) - No alert because threshold_ref not met
    hour3: 100 events (ref: 20, cur: 200) - No alert because ref window not filled
    hour4: 100 events (ref: 120, cur: 200) - No alert because spike_height not met

    hour1: 0 events (ref: 0, cur: 0) - No alert because threshold_ref not met
    hour1: 20 events (ref: 0, cur: 20) - No alert because threshold_ref not met
    hour2: 100 events (ref: 0, cur: 120) - No alert because threshold_ref not met
    hour3: 100 events (ref: 20, cur: 200) - Alert because threshold_ref and spike_height met

    hour1: 1 events (ref: 0, cur: 1) - No alert because threshold_ref not met
    hour2: 2 events (ref: 0, cur: 3) - No alert because threshold_ref not met
    hour3: 2 events (ref: 1, cur: 15) - No alert because threshold_ref not met
    hour4: 1000 events (ref: 3, cur: 1002) - No alert because threshold_ref not met
    hour5: 2 events (ref: 4, cur: 1002) - No alert because threshold_ref not met
    hour6: 4 events: ref(1002, cur: 6) - No alert because spike_height not met

    hour1: 1000 events (ref: 0, cur: 1000) - No alert because threshold_ref not met
    hour2: 0 events (ref: 0, cur: 1000) - No alert because threshold_ref not met
    hour3: 0 events (ref: 1000, cur: 0) - No alert because spike_height not met
    hour4: 0 events (ref: 1000, cur: 0) - No alert because spike_height not met
    hour5: 1000 events (ref: 0, cur: 1000) - No alert because threshold_ref not met
    hour6: 1050 events (ref: 0, cur: 2050)- No alert because threshold_ref not met
    hour7: 1075 events (ref: 1000, cur: 2125) Alert because threshold_ref and spike_height met

    " Alert if at least 100 events occur within two hours and less than a fifth of that number occured in the previous two hours. "
    timeframe: hours: 2
    spike_height: 5
    threshold_cur: 100

    hour1: 1000 events (ref: 0, cur: 1000) - No alert because ref window not filled

    hour1: 2 events (ref: 0, cur: 2) - No alert because threshold_cur not met
    hour2: 1 events (ref: 0, cur: 3) - No alert because threshold_cur not met
    hour3: 20 events (ref: 2, cur: 21) - No alert because threshold_cur not met
    hour4: 81 events (ref: 3, cur: 101) - Alert because threshold_cur and spie_height met

    hour1: 10 events (ref: 0, cur: 10) - No alert because ref window not filled
    hour2: 20 events (ref: 0, cur: 30) - No alert because ref window not filled
    hour3: 40 events (ref: 10, cur: 60) - No alert because threshold_cur not met
    hour4: 80 events (ref: 30, cur: 120) - No alert because spike_height not met
    hour5: 200 events (ref: 60, cur: 280) - No alert because spike_height not met

``query_key``: The number of events is counted separately for each unique ``query_key`` field. If this option
is set, the field must be present for all events.

``alert_on_new_events``: This option is only used if ``query_key`` is set. When this is set to true, any new ``query_key`` encountered may
trigger an immediate alert. When set to false, baseline must be established for each new ``query_key`` value, and then subsequent spikes may
cause alerts. Baseline is established after ``timeframe`` has elapsed twice since first occurrence.

``top_count_keys``: A list of fields. ElastAlert will tell you the count for the top 5 most common values for each of the fields.
For example, if there are 100 events in a spike, and ``top_count_keys`` is ``["username"]``, the alert will say how many of the 100 events
have each username, for the top 5 usernames.

``top_count_number``: The number of terms to list if ``top_count_keys`` is set.

``use_count_query``: If true, ElastAlert will poll elasticsearch using the count api, and not download all of the matching documents. This is
useful is you care only about numbers and not the actual data. It should also be used if you expect a large number of query hits, in the order
of tens of thousands or more. It cannot be used with ``top_count_keys``. If ``top_count_keys`` is absent, it is turned on by default.

``use_terms_query``: If true, ElastAlert will make an aggregation query against Elasticsearch to get counts of documents matching
each unique value of ``query_key``.
Similarly to ``use_count_query``, this cannot be used with ``top_count_keys``, but MUST be used with ``query_key``.

Flatline
~~~~~~~~

``flatline``: This rule matches when the total number of events is under a given ``threshold`` for a time period.

This rule requires two additional options:

``threshold``: The minimum number of events for an alert not to be triggered.

``timeframe``: The time period that must contain less than ``threshold`` events.

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

Alert Content
~~~~~~~~~~~~~~~

There are several ways to format the body text of the various types of events. In EBNF::

    rule_name           = name
    alert_text          = alert_text
    ruletype_text       = Depends on type
    top_counts_header   = "The following are the top event counts by ", top_count_key
    top_counts_value    = Value, ": ", Count
    top_counts          = top_counts_header, LF, top_counts_value
    field_values        = Field, ": ", Value
    
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

Email
~~~~~

This alert will send an email. It connects to an smtp server located at ``smtp_host``, or localhost by default.

This alert requires one additional option:

``email``: An address or list of addresses to sent the alert to.

Optional:

``smtp_host``: The SMTP host to use, defaults to localhost.

``email_reply_to``: This sets the Reply-To header in the email. By default, the from address is ElastAlert@ and the domain will be set
by the smtp server.

Jira
~~~~~

The JIRA alerter will open a ticket on jira whenever an alert is triggered. You must have a service account for ElastAlert to connect with.
The credentials of the service account are loaded from a separate file.

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

``jira_label``: The label to add to the JIRA ticket.

Debug
~~~~~~

The debug alerter will log the alert information using the Python logger at the info level.

