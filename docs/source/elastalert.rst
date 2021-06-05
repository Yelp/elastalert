ElastAlert 2 - Automated rule-based alerting for Elasticsearch
**************************************************************

ElastAlert is a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch.

If you have data being written into Elasticsearch in near real time and want to be alerted when that data matches certain patterns, ElastAlert is the tool for you.

Overview
========

We designed ElastAlert to be :ref:`reliable <reliability>`, highly :ref:`modular <modularity>`, and easy to :ref:`set up <tutorial>` and :ref:`configure <configuration>`.

It works by combining Elasticsearch with two types of components, rule types and alerts.
Elasticsearch is periodically queried and the data is passed to the rule type, which determines when
a match is found. When a match occurs, it is given to one or more alerts, which take action based on the match.

This is configured by a set of rules, each of which defines a query, a rule type, and a set of alerts.

Several rule types with common monitoring paradigms are included with ElastAlert:

- "Match where there are X events in Y time" (``frequency`` type)
- "Match when the rate of events increases or decreases" (``spike`` type)
- "Match when there are less than X events in Y time" (``flatline`` type)
- "Match when a certain field matches a blacklist/whitelist" (``blacklist`` and ``whitelist`` type)
- "Match on any event matching a given filter" (``any`` type)
- "Match when a field has two different values within some time" (``change`` type)

Currently, we have support built in for these alert types:

- Alerta
- AWS SES (Amazon Simple Email Service)
- AWS SNS (Amazon Simple Notification Service)
- Chatwork
- Command
- Datadog
- Debug
- Dingtalk
- Discord
- Email
- Exotel
- Gitter
- GoogleChat
- HTTP POST
- JIRA
- Line Notify
- Mattermost
- Microsoft Teams
- OpsGenie
- PagerDuty
- PagerTree
- Rocket.Chat
- Squadcast
- ServiceNow
- Slack
- Splunk On-Call (Formerly VictorOps)
- Stomp
- Telegram
- TheHive
- Twilio
- Zabbix

Additional rule types and alerts can be easily imported or written. (See :ref:`Writing rule types <writingrules>` and :ref:`Writing alerts <writingalerts>`)

In addition to this basic usage, there are many other features that make alerts more useful:

- Alerts link to Kibana dashboards
- Aggregate counts for arbitrary fields
- Combine alerts into periodic reports
- Separate alerts by using a unique key field
- Intercept and enhance match data

To get started, check out :ref:`Running ElastAlert For The First Time <tutorial>`.

.. _reliability:

Reliability
===========

ElastAlert has several features to make it more reliable in the event of restarts or Elasticsearch unavailability:

- ElastAlert :ref:`saves its state to Elasticsearch <metadata>` and, when started, will resume where previously stopped
- If Elasticsearch is unresponsive, ElastAlert will wait until it recovers before continuing
- Alerts which throw errors may be automatically retried for a period of time

.. _modularity:

Modularity
==========

ElastAlert has three main components that may be imported as a module or customized:

Rule types
----------

The rule type is responsible for processing the data returned from Elasticsearch. It is initialized with the rule configuration, passed data
that is returned from querying Elasticsearch with the rule's filters, and outputs matches based on this data. See :ref:`Writing rule types <writingrules>`
for more information.

Alerts
------

Alerts are responsible for taking action based on a match. A match is generally a dictionary containing values from a document in Elasticsearch,
but may contain arbitrary data added by the rule type. See :ref:`Writing alerts <writingalerts>` for more information.

Enhancements
------------

Enhancements are a way of intercepting an alert and modifying or enhancing it in some way. They are passed the match dictionary before it is given
to the alerter. See :ref:`Enhancements` for more information.

.. _configuration:

Configuration
=============

ElastAlert has a global configuration file, ``config.yaml``, which defines several aspects of its operation:

``buffer_time``: ElastAlert will continuously query against a window from the present to ``buffer_time`` ago.
This way, logs can be back filled up to a certain extent and ElastAlert will still process the events. This
may be overridden by individual rules. This option is ignored for rules where ``use_count_query`` or ``use_terms_query``
is set to true. Note that back filled data may not always trigger count based alerts as if it was queried in real time.

``es_host``: The host name of the Elasticsearch cluster where ElastAlert records metadata about its searches.
When ElastAlert is started, it will query for information about the time that it was last run. This way,
even if ElastAlert is stopped and restarted, it will never miss data or look at the same events twice. It will also specify the default cluster for each rule to run on.
The environment variable ``ES_HOST`` will override this field.

``es_port``: The port corresponding to ``es_host``. The environment variable ``ES_PORT`` will override this field.

``use_ssl``: Optional; whether or not to connect to ``es_host`` using TLS; set to ``True`` or ``False``.
The environment variable ``ES_USE_SSL`` will override this field.

``verify_certs``: Optional; whether or not to verify TLS certificates; set to ``True`` or ``False``. The default is ``True``.

``ssl_show_warn``: Optional; suppress TLS and certificate related warnings; set to ``True`` or ``False``. The default is ``True``.

``client_cert``: Optional; path to a PEM certificate to use as the client certificate.

``client_key``: Optional; path to a private key file to use as the client key.

``ca_certs``: Optional; path to a CA cert bundle to use to verify SSL connections

``es_username``: Optional; basic-auth username for connecting to ``es_host``. The environment variable ``ES_USERNAME`` will override this field.

``es_password``: Optional; basic-auth password for connecting to ``es_host``. The environment variable ``ES_PASSWORD`` will override this field.

``es_bearer``: Optional; Bearer token for connecting to ``es_host``. The environment variable ``ES_BEARER`` will override this field. This authentication option will override the password authentication option.

``es_api_key``: Optional; Base64 api-key token for connecting to ``es_host``. The environment variable ``ES_API_KEY`` will override this field. This authentication option will override both the bearer and the password authentication options.

``es_url_prefix``: Optional; URL prefix for the Elasticsearch endpoint.  The environment variable ``ES_URL_PREFIX`` will override this field.

``es_send_get_body_as``: Optional; Method for querying Elasticsearch - ``GET``, ``POST`` or ``source``. The default is ``GET``

``es_conn_timeout``: Optional; sets timeout for connecting to and reading from ``es_host``; defaults to ``20``.

``rules_loader``: Optional; sets the loader class to be used by ElastAlert to retrieve rules and hashes.
Defaults to ``FileRulesLoader`` if not set.

``rules_folder``: The name of the folder or a list of folders which contains rule configuration files. ElastAlert will load all
files in this folder, and all subdirectories, that end in .yaml. If the contents of this folder change, ElastAlert will load, reload
or remove rules based on their respective config files. (only required when using ``FileRulesLoader``).

``scan_subdirectories``: Optional; Sets whether or not ElastAlert should recursively descend the rules directory - ``true`` or ``false``. The default is ``true``

``run_every``: How often ElastAlert should query Elasticsearch. ElastAlert will remember the last time
it ran the query for a given rule, and periodically query from that time until the present. The format of
this field is a nested unit of time, such as ``minutes: 5``. This is how time is defined in every ElastAlert
configuration.

``misfire_grace_time``: If the rule scheduler is running behind, due to large numbers of rules or long-running rules, this grace time settings allows a rule to still be executed, provided its next scheduled runt time is no more than this grace period, in seconds, overdue. The default is 5 seconds.

``writeback_index``: The index on ``es_host`` to use.

``max_query_size``: The maximum number of documents that will be downloaded from Elasticsearch in a single query. The
default is 10,000, and if you expect to get near this number, consider using ``use_count_query`` for the rule. If this
limit is reached, ElastAlert will `scroll <https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html>`_
using the size of ``max_query_size`` through the set amount of pages, when ``max_scrolling_count`` is set or until processing all results.

``max_scrolling_count``: The maximum amount of pages to scroll through. The default is ``0``, which means the scrolling has no limit.
For example if this value is set to ``5`` and the ``max_query_size`` is set to ``10000`` then ``50000`` documents will be downloaded at most.

``max_threads``: The maximum number of concurrent threads available to process scheduled rules. Large numbers of long-running rules may require this value be increased, though this could overload the Elasticsearch cluster if too many complex queries are running concurrently. Default is 10.

``scroll_keepalive``: The maximum time (formatted in `Time Units <https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#time-units>`_) the scrolling context should be kept alive. Avoid using high values as it abuses resources in Elasticsearch, but be mindful to allow sufficient time to finish processing all the results.

``max_aggregation``: The maximum number of alerts to aggregate together. If a rule has ``aggregation`` set, all
alerts occuring within a timeframe will be sent together. The default is 10,000.

``old_query_limit``: The maximum time between queries for ElastAlert to start at the most recently run query.
When ElastAlert starts, for each rule, it will search ``elastalert_metadata`` for the most recently run query and start
from that time, unless it is older than ``old_query_limit``, in which case it will start from the present time. The default is one week.

``disable_rules_on_error``: If true, ElastAlert will disable rules which throw uncaught (not EAException) exceptions. It
will upload a traceback message to ``elastalert_metadata`` and if ``notify_email`` is set, send an email notification. The
rule will no longer be run until either ElastAlert restarts or the rule file has been modified. This defaults to True.

``show_disabled_rules``: If true, ElastAlert show the disable rules' list when finishes the execution. This defaults to True.

``notify_email``: An email address, or list of email addresses, to which notification emails will be sent. Currently,
only an uncaught exception will send a notification email. The from address, SMTP host, and reply-to header can be set
using ``from_addr``, ``smtp_host``, and ``email_reply_to`` options, respectively. By default, no emails will be sent.

``from_addr``: The address to use as the from header in email notifications.
This value will be used for email alerts as well, unless overwritten in the rule config. The default value
is "ElastAlert".

``smtp_host``: The SMTP host used to send email notifications. This value will be used for email alerts as well,
unless overwritten in the rule config. The default is "localhost".

``email_reply_to``: This sets the Reply-To header in emails. The default is the recipient address.

``aws_region``: This makes ElastAlert to sign HTTP requests when using Amazon Elasticsearch Service. It'll use instance role keys to sign the requests.
The environment variable ``AWS_DEFAULT_REGION`` will override this field.

``boto_profile``: Deprecated! Boto profile to use when signing requests to Amazon Elasticsearch Service, if you don't want to use the instance role keys.

``profile``: AWS profile to use when signing requests to Amazon Elasticsearch Service, if you don't want to use the instance role keys.
The environment variable ``AWS_DEFAULT_PROFILE`` will override this field.

``replace_dots_in_field_names``: If ``True``, ElastAlert replaces any dots in field names with an underscore before writing documents to Elasticsearch.
The default value is ``False``. Elasticsearch 2.0 - 2.3 does not support dots in field names.

``string_multi_field_name``: If set, the suffix to use for the subfield for string multi-fields in Elasticsearch.
The default value is ``.raw`` for Elasticsearch 2 and ``.keyword`` for Elasticsearch 5.

``add_metadata_alert``: If set, alerts will include metadata described in rules (``category``, ``description``, ``owner`` and ``priority``); set to ``True`` or ``False``. The default is ``False``.

``skip_invalid``: If ``True``, skip invalid files instead of exiting.

``jinja_root_name``: When using a Jinja template, specify the name of the root field name in the template. The default is ``_data``.

``jinja_template_path``: When using a Jinja template, specify filesystem path to template, this overrides the default behaviour of using alert_text as the template.

Logging
-------

By default, ElastAlert uses a simple basic logging configuration to print log messages to standard error.
You can change the log level to ``INFO`` messages by using the ``--verbose`` or ``--debug`` command line options.

If you need a more sophisticated logging configuration, you can provide a full logging configuration
in the config file. This way you can also configure logging to a file, to Logstash and
adjust the logging format.

For details, see the end of ``config.yaml.example`` where you can find an example logging
configuration.
