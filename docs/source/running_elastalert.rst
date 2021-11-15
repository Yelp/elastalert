.. _tutorial:

Running ElastAlert 2
********************

ElastAlert 2 can easily be run as :ref:`a Docker container<docker-instructions>`
or directly on your machine as :ref:`a Python package<python-instructions>`.
If you are not interested in modifying the internals of  ElastAlert 2, the Docker
container is recommended for ease of use.

.. _elastalert-arguments:

Configuration flags
===================

However you choose to run ElastAlert 2, the ElastAlert 2 process is started by invoking
``python elastalert/elastalert.py``.

This command accepts several configuration flags:

``--config`` will specify the configuration file to use. The default is
``config.yaml``. See :ref:`here<configuration>` to understand what behaviour
can be configured in this file.

``--debug`` will run ElastAlert 2 in debug mode. This will increase the logging
verboseness, change all alerts to ``DebugAlerter``, which prints alerts and
suppresses their normal action, and skips writing search and alert metadata back
to Elasticsearch. Not compatible with `--verbose`.

``--end <timestamp>`` will force ElastAlert 2 to stop querying after the given
time, instead of the default, querying to the present time. This really only
makes sense when running standalone. The timestamp is formatted as
``YYYY-MM-DDTHH:MM:SS`` (UTC) or with timezone ``YYYY-MM-DDTHH:MM:SS-XX:00``
(UTC-XX).

``--es_debug`` will enable logging for all queries made to Elasticsearch.

``--es_debug_trace <trace.log>`` will enable logging curl commands for all
queries made to Elasticsearch to the specified log file. ``--es_debug_trace`` is
passed through to `elasticsearch.py
<http://elasticsearch-py.readthedocs.io/en/master/index.html#logging>`_ which
logs `localhost:9200` instead of the actual ``es_host``:``es_port``.

``--pin_rules`` will stop ElastAlert 2 from loading, reloading or removing rules
based on changes to their config files.

``--prometheus_port`` exposes ElastAlert 2 `Prometheus metrics <https://elastalert2.readthedocs.io/en/latest/recipes/exposing_rule_metrics.html>`_ on the specified
port. Prometheus metrics disabled by default.

``--rule <rule.yaml>`` will only run the given rule. The rule file may be a
complete file path or a filename in ``rules_folder`` or its subdirectories.

``--silence <unit>=<number>`` will silence the alerts for a given rule for a
period of time. The rule must be specified using ``--rule``. <unit> is one of
days, weeks, hours, minutes or seconds. <number> is an integer. For example,
``--rule noisy_rule.yaml --silence hours=4`` will stop noisy_rule from
generating any alerts for 4 hours.

``--silence_qk_value <value`` will silence the rule only for the given 
query key value. This parameter is intended to be used with the ``--rule`` 
parameter.

``--start <timestamp>`` will force ElastAlert 2 to begin querying from the given
time, instead of the default, querying from the present. The timestamp should be
ISO8601, e.g.  ``YYYY-MM-DDTHH:MM:SS`` (UTC) or with timezone
``YYYY-MM-DDTHH:MM:SS-08:00`` (PST). Note that if querying over a large date
range, no alerts will be sent until that rule has finished querying over the
entire time period. To force querying from the current time, use "NOW".

``--verbose`` will increase the logging verboseness, which allows you to see
information about the state of queries. Not compatible with `--debug`.

.. _docker-instructions:

As a Docker container
=====================

If you're interested in a pre-built Docker image check out the
elastalert2 container image on `Docker Hub <https://hub.docker.com/r/jertel/elastalert2>`_ or `GitHub Container Registry <https://github.com/jertel/elastalert2/pkgs/container/elastalert2%2Felastalert2>`_. Both images are published for each release. Use GitHub Container Registry if you are running into Docker Hub usage limits.

Be aware that the ``latest`` tag of the image represents the latest commit into
the master branch. If you prefer to upgrade more slowly you will need utilize a
versioned tag, such as ``2.2.3`` instead, or ``2`` if you are comfortable with
always using the latest released version of ElastAlert 2.

A properly configured config.yaml file must be mounted into the container during
startup of the container. Use the `example file
<https://github.com/jertel/elastalert2/blob/master/examples/config.yaml.example>`_
provided as a template, and once saved locally to a file such as
``/tmp/elastalert.yaml``, run the container as follows:

via Docker Hub (hub.docker.com)

.. code-block::

    docker run -d -v /tmp/elastalert.yaml:/opt/elastalert/config.yaml jertel/elastalert2

via GitHub Container Registry (ghcr.io)

.. code-block::

    docker run -d -v /tmp/elastalert.yaml:/opt/elastalert/config.yaml ghcr.io/jertel/elastalert2/elastalert2

To build the image locally run the following command:

.. code-block::

    docker build . -t elastalert2

.. _kubernetes-instructions:

As a Kubernetes deployment
==========================

The Docker container for ElastAlert 2 can be used directly as a Kubernetes
deployment, but for convenience, a Helm chart is also available. See the
instructions provided `on Github
<https://github.com/jertel/elastalert2/blob/master/chart/elastalert2/README.md>`_
for more information on how to install, configure, and run the chart.

.. _python-instructions:

As a Python package
===================

Requirements
------------

- Elasticsearch
- ISO8601 or Unix timestamped data
- Python 3.9
- pip
- Packages on Ubuntu 21.x: build-essential python3-pip python3.9 python3.9-dev libffi-dev libssl-dev

If you want to install python 3.9 on CentOS, please install python 3.9 from the source code after installing 'Development Tools'.

Downloading and Configuring
---------------------------

You can either install the latest released version of ElastAlert 2 using pip::

    $ pip install elastalert2

or you can clone the ElastAlert2 repository for the most recent changes::

    $ git clone https://github.com/jertel/elastalert2.git

Install the module::

    $ pip install "setuptools>=11.3"
    $ python setup.py install

Next, open up ``examples/config.yaml.example``. In it, you will find several configuration
options. ElastAlert 2 may be run without changing any of these settings.

``rules_folder`` is where ElastAlert 2 will load rule configuration files from. It
will attempt to load every .yaml file in the folder. Without any valid rules,
ElastAlert 2 will not start. ElastAlert 2 will also load new rules, stop running
missing rules, and restart modified rules as the files in this folder change.
For this tutorial, we will use the ``examples/rules`` folder.

``run_every`` is how often ElastAlert 2 will query Elasticsearch.

``buffer_time`` is the size of the query window, stretching backwards from the
time each query is run. This value is ignored for rules where
``use_count_query`` or ``use_terms_query`` is set to true.

``es_host`` is the primary address of an Elasticsearch cluster where ElastAlert 2 will
store data about its state, queries run, alerts, and errors. Each rule may also
use a different Elasticsearch host to query against. For multiple host Elasticsearch 
clusters see ``es_hosts`` parameter.

``es_port`` is the port corresponding to ``es_host``.

``es_hosts`` is the list of addresses of the nodes of the Elasticsearch cluster. This
parameter can be used for high availability purposes, but the primary host must also
be specified in the ``es_host`` parameter. The ``es_hosts`` parameter can be overridden 
within each rule. This value can be specified as ``host:port`` if overriding the default 
port.

``use_ssl``: Optional; whether or not to connect to ``es_host`` using TLS; set
to ``True`` or ``False``.

``verify_certs``: Optional; whether or not to verify TLS certificates; set to
``True`` or ``False``. The default is ``True``

``ssl_show_warn``: Optional; suppress TLS and certificate related warnings; set
to ``True`` or ``False``. The default is ``True``.

``client_cert``: Optional; path to a PEM certificate to use as the client
certificate

``client_key``: Optional; path to a private key file to use as the client key

``ca_certs``: Optional; path to a CA cert bundle to use to verify SSL
connections

``es_username``: Optional; basic-auth username for connecting to ``es_host``.

``es_password``: Optional; basic-auth password for connecting to ``es_host``.

``es_bearer``: Optional; bearer token authorization for connecting to
``es_host``. If bearer token is specified, login and password are ignored.

``es_url_prefix``: Optional; URL prefix for the Elasticsearch endpoint.

``statsd_instance_tag``: Optional; prefix for statsd metrics.

``statsd_host``: Optional; statsd host.

``es_send_get_body_as``: Optional; Method for querying Elasticsearch - ``GET``,
``POST`` or ``source``. The default is ``GET``

``writeback_index`` is the name of the index in which ElastAlert 2 will store
data. We will create this index later.

``alert_time_limit`` is the retry window for failed alerts.

Save the file as ``config.yaml``

Setting Up Elasticsearch
------------------------

ElastAlert 2 saves information and metadata about its queries and its alerts back
to Elasticsearch. This is useful for auditing, debugging, and it allows
ElastAlert 2 to restart and resume exactly where it left off. This is not required
for ElastAlert 2 to run, but highly recommended.

First, we need to create an index for ElastAlert 2 to write to by running
``elastalert-create-index`` and following the instructions. Note that this manual 
step is only needed by users that run ElastAlert 2 directly on the host, whereas 
container users will automatically see these indexes created on startup.::

    $ elastalert-create-index
    New index name (Default elastalert_status)
    Name of existing index to copy (Default None)
    New index elastalert_status created
    Done!

For information about what data will go here, see :ref:`ElastAlert 2 Metadata
Index <metadata>`.

Creating a Rule
---------------

Each rule defines a query to perform, parameters on what triggers a match, and a
list of alerts to fire for each match. We are going to use
``examples/rules/example_frequency.yaml`` as a template::

    # From examples/rules/example_frequency.yaml
    es_host: elasticsearch.example.com
    es_port: 14900
    name: Example rule
    type: frequency
    index: logstash-*
    num_events: 50
    timeframe:
      hours: 4
    filter:
    - term:
        some_field: "some_value"
    alert:
    - "email"
    email:
    - "elastalert@example.com"

``es_host`` and ``es_port`` should point to the Elasticsearch cluster we want to
query.

``name`` is the unique name for this rule. ElastAlert 2 will not start if two
rules share the same name.

``type``: Each rule has a different type which may take different parameters.
The ``frequency`` type means "Alert when more than ``num_events`` occur within
``timeframe``." For information other types, see :ref:`Rule types <ruletypes>`.

``index``: The name of the index(es) to query. If you are using Logstash, by
default the indexes will match ``"logstash-*"``.

``num_events``: This parameter is specific to ``frequency`` type and is the
threshold for when an alert is triggered.

``timeframe`` is the time period in which ``num_events`` must occur.

``filter`` is a list of Elasticsearch filters that are used to filter results.
Here we have a single term filter for documents with ``some_field`` matching
``some_value``. See :ref:`Writing Filters For Rules <writingfilters>` for more
information. If no filters are desired, it should be specified as an empty list:
``filter: []``

``alert`` is a list of alerts to run on each match. For more information on
alert types, see :ref:`Alerts <alerts>`. The email alert requires an SMTP server
for sending mail. By default, it will attempt to use localhost. This can be
changed with the ``smtp_host`` option.

``email`` is a list of addresses to which alerts will be sent.

There are many other optional configuration options, see :ref:`Common
configuration options <commonconfig>`.

All documents must have a timestamp field. ElastAlert 2 will try to use
``@timestamp`` by default, but this can be changed with the ``timestamp_field``
option. By default, ElastAlert 2 uses ISO8601 timestamps, though unix timestamps
are supported by setting ``timestamp_type``.

As is, this rule means "Send an email to elastalert@example.com when there are
more than 50 documents with ``some_field == some_value`` within a 4 hour
period."

Testing Your Rule
-----------------

Running the ``elastalert-test-rule`` tool will test that your config file
successfully loads and run it in debug mode over the last 24 hours::

    $ elastalert-test-rule examples/rules/example_frequency.yaml

If you want to specify a configuration file to use, you can run it with the
config flag::

    $ elastalert-test-rule --config <path-to-config-file> examples/rules/example_frequency.yaml

The configuration preferences will be loaded as follows:
    1. Configurations specified in the yaml file.
    2. Configurations specified in the config file, if specified.
    3. Default configurations, for the tool to run.

See :ref:`the testing section for more details <testing>`

Running ElastAlert 2
--------------------

There are two ways of invoking ElastAlert 2. As a daemon, through Supervisor
(http://supervisord.org/), or directly with Python. For easier debugging
purposes in this tutorial, we will invoke it directly::

    $ python -m elastalert.elastalert --verbose --rule example_frequency.yaml  # or use the entry point: elastalert --verbose --rule ...
    No handlers could be found for logger "Elasticsearch"
    INFO:root:Queried rule Example rule from 1-15 14:22 PST to 1-15 15:07 PST: 5 hits
    INFO:Elasticsearch:POST http://elasticsearch.example.com:14900/elastalert_status/elastalert_status?op_type=create [status:201 request:0.025s]
    INFO:root:Ran Example rule from 1-15 14:22 PST to 1-15 15:07 PST: 5 query hits (0 already seen), 0 matches, 0 alerts sent
    INFO:root:Sleeping for 297 seconds

ElastAlert 2 uses the python logging system and ``--verbose`` sets it to display
INFO level messages. ``--rule example_frequency.yaml`` specifies the rule to
run, otherwise ElastAlert 2 will attempt to load the other rules in the
``examples/rules`` folder.

Let's break down the response to see what's happening.

``Queried rule Example rule from 1-15 14:22 PST to 1-15 15:07 PST: 5 hits``

ElastAlert 2 periodically queries the most recent ``buffer_time`` (default 45
minutes) for data matching the filters. Here we see that it matched 5 hits:

.. code-block::

    POST http://elasticsearch.example.com:14900/elastalert_status/elastalert_status?op_type=create [status:201 request:0.025s]

This line showing that ElastAlert 2 uploaded a document to the elastalert_status
index with information about the query it just made:

.. code-block::

    Ran Example rule from 1-15 14:22 PST to 1-15 15:07 PST: 5 query hits (0 already seen), 0 matches, 0 alerts sent

The line means ElastAlert 2 has finished processing the rule. For large time
periods, sometimes multiple queries may be run, but their data will be processed
together. ``query hits`` is the number of documents that are downloaded from
Elasticsearch, ``already seen`` refers to documents that were already counted in
a previous overlapping query and will be ignored, ``matches`` is the number of
matches the rule type outputted, and ``alerts sent`` is the number of alerts
actually sent. This may differ from ``matches`` because of options like
``realert`` and ``aggregation`` or because of an error.

``Sleeping for 297 seconds``

The default ``run_every`` is 5 minutes, meaning ElastAlert 2 will sleep until 5
minutes have elapsed from the last cycle before running queries for each rule
again with time ranges shifted forward 5 minutes.

Say, over the next 297 seconds, 46 more matching documents were added to
Elasticsearch::


    INFO:root:Queried rule Example rule from 1-15 14:27 PST to 1-15 15:12 PST: 51 hits
    ...
    INFO:root:Sent email to ['elastalert@example.com']
    ...
    INFO:root:Ran Example rule from 1-15 14:27 PST to 1-15 15:12 PST: 51 query hits, 1 matches, 1 alerts sent

The body of the email will contain something like::

    Example rule

    At least 50 events occurred between 1-15 11:12 PST and 1-15 15:12 PST

    @timestamp: 2015-01-15T15:12:00-08:00

If an error occurred, such as an unreachable SMTP server, you may see:

.. code-block::

    ERROR:root:Error while running alert email: Error connecting to SMTP host: [Errno 61] Connection refused


Note that if you stop ElastAlert 2 and then run it again later, it will look up
``elastalert_status`` and begin querying at the end time of the last query. This
is to prevent duplication or skipping of alerts if ElastAlert 2 is restarted.

By using the ``--debug`` flag instead of ``--verbose``, the body of email will
instead be logged and the email will not be sent. In addition, the queries will
not be saved to ``elastalert_status``.

Disabling a Rule
----------------

To stop a rule from executing, add or adjust the `is_enabled` option inside the
rule's YAML file to `false`. When ElastAlert 2 reloads the rules it will detect
that the rule has been disabled and prevent it from executing. The rule reload
interval defaults to 5 minutes but can be adjusted via the `run_every`
configuration option.

Optionally, once a rule has been disabled it is safe to remove the rule file, if
there is no intention of re-activating the rule. However, be aware that removing
a rule file without first disabling it will _not_ disable the rule!

