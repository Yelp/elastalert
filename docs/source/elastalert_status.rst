.. _metadata:

ElastAlert 2 Metadata Index
===========================

ElastAlert 2 uses Elasticsearch to store various information about its state. This not only allows for some
level of auditing and debugging of ElastAlert 2's operation, but also to avoid loss of data or duplication of alerts
when ElastAlert 2 is shut down, restarted, or crashes. This cluster and index information is defined
in the global config file with ``es_host``, ``es_port`` and ``writeback_index``. ElastAlert 2 must be able
to write to this index. The script, ``elastalert-create-index`` will create the index with the correct mapping
for you, and optionally copy the documents from an existing ElastAlert 2 writeback index. Run it and it will
prompt you for the cluster information.

ElastAlert 2 will create three different types of documents in the writeback index:

elastalert_status
~~~~~~~~~~~~~~~~~

``elastalert_status`` is a log of the queries performed for a given rule and contains:

- ``@timestamp``: The time when the document was uploaded to Elasticsearch. This is after a query has been run and the results have been processed.
- ``rule_name``: The name of the corresponding rule.
- ``starttime``: The beginning of the timestamp range the query searched.
- ``endtime``: The end of the timestamp range the query searched.
- ``hits``: The number of results from the query.
- ``matches``: The number of matches that the rule returned after processing the hits. Note that this does not necessarily mean that alerts were triggered.
- ``time_taken``: The number of seconds it took for this query to run.

``elastalert_status`` is what ElastAlert 2 will use to determine what time range to query when it first starts to avoid duplicating queries.
For each rule, it will start querying from the most recent endtime. If ElastAlert 2 is running in debug mode, it will still attempt to base
its start time by looking for the most recent search performed, but it will not write the results of any query back to Elasticsearch.

elastalert
~~~~~~~~~~

``elastalert`` is a log of information about every alert triggered and contains:

- ``@timestamp``: The time when the document was uploaded to Elasticsearch. This is not the same as when the alert was sent, but rather when the rule outputs a match.
- ``rule_name``: The name of the corresponding rule.
- ``alert_info``: This contains the output of Alert.get_info, a function that alerts implement to give some relevant context to the alert type. This may contain alert_info.type, alert_info.recipient, or any number of other sub fields.
- ``alert_sent``: A boolean value as to whether this alert was actually sent or not. It may be false in the case of an exception or if it is part of an aggregated alert.
- ``alert_time``: The time that the alert was or will be sent. Usually, this is the same as @timestamp, but may be some time in the future, indicating when an aggregated alert will be sent.
- ``match_body``: This is the contents of the match dictionary that is used to create the alert. The subfields may include a number of things containing information about the alert.
- ``alert_exception``: This field is only present when the alert failed because of an exception occurring, and will contain the exception information.
- ``aggregate_id``: This field is only present when the rule is configured to use aggregation. The first alert of the aggregation period will contain an alert_time set to the aggregation time into the future, and subsequent alerts will contain the document ID of the first. When the alert_time is reached, all alerts with that aggregate_id will be sent together.

elastalert_error
~~~~~~~~~~~~~~~~

When an error occurs in ElastAlert 2, it is written to both Elasticsearch and to stderr. The ``elastalert_error`` type contains:

- ``@timestamp``: The time when the error occurred.
- ``message``: The error or exception message.
- ``traceback``: The traceback from when the error occurred.
- ``data``: Extra information about the error. This often contains the name of the rule which caused the error.

silence
~~~~~~~

``silence`` is a record of when alerts for a given rule will be suppressed, either because of a ``realert`` setting or from using --silence. When
an alert with ``realert`` is triggered, a ``silence`` record will be written with ``until`` set to the alert time plus ``realert``.

- ``@timestamp``: The time when the document was uploaded to Elasticsearch.
- ``rule_name``: The name of the corresponding rule.
- ``until``: The timestamp when alerts will begin being sent again.
- ``exponent``: The exponential factor which multiplies ``realert``. The length of this silence is equal to ``realert`` * 2**exponent. This will
  be 0 unless ``exponential_realert`` is set.

Whenever an alert is triggered, ElastAlert 2 will check for a matching ``silence`` document, and if the ``until`` timestamp is in the future, it will ignore
the alert completely. See the :ref:`Running ElastAlert 2 <elastalert-arguments>` section for information on how to silence an alert.
