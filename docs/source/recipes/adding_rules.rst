.. _writingrules:

Adding a New Rule Type
======================

This document describes how to create a new rule type. Built in rule types live in ``elastalert/ruletypes.py``
and are subclasses of ``RuleType``. At the minimum, your rule needs to implement ``add_data``.

Your class may implement several functions from ``RuleType``:

.. code-block:: python

    class AwesomeNewRule(RuleType):
        # ...
        def add_data(self, data):
            # ...
        def get_match_str(self, match):
            # ...
        def garbage_collect(self, timestamp):
            # ...

You can import new rule types by specifying the type as ``module.file.RuleName``, where module is the name of a Python module, or folder
containing ``__init__.py``, and file is the name of the Python file containing a ``RuleType`` subclass named ``RuleName``.

Basics
------

The ``RuleType`` instance remains in memory while ElastAlert is running, receives data, keeps track of its state,
and generates matches. Several important member properties are created in the ``__init__`` method of ``RuleType``:

``self.rules``: This dictionary is loaded from the rule configuration file. If there is a ``timeframe`` configuration
option, this will be automatically converted to a ``datetime.timedelta`` object when the rules are loaded.

``self.matches``: This is where ElastAlert 2 checks for matches from the rule. Whatever information is relevant to the match
(generally coming from the fields in Elasticsearch) should be put into a dictionary object and
added to ``self.matches``. ElastAlert 2 will pop items out periodically and send alerts based on these objects. It is
recommended that you use ``self.add_match(match)`` to add matches. In addition to appending to ``self.matches``,
``self.add_match`` will convert the datetime ``@timestamp`` back into an ISO8601 timestamp.

``self.required_options``: This is a set of options that must exist in the configuration file. ElastAlert 2 will
ensure that all of these fields exist before trying to instantiate a ``RuleType`` instance.

add_data(self, data):
---------------------

When ElastAlert 2 queries Elasticsearch, it will pass all of the hits to the rule type by calling ``add_data``.
``data`` is a list of dictionary objects which contain all of the fields in ``include``, ``query_key`` and ``compare_key``
if they exist, and ``@timestamp`` as a datetime object. They will always come in chronological order sorted by '@timestamp'.

get_match_str(self, match):
---------------------------

Alerts will call this function to get a human readable string about a match for an alert. Match will be the same
object that was added to ``self.matches``, and ``rules`` the same as ``self.rules``. The ``RuleType`` base implementation
will return an empty string. Note that by default, the alert text will already contain the key-value pairs from the match. This
should return a string that gives some information about the match in the context of this specific RuleType.

garbage_collect(self, timestamp):
---------------------------------

This will be called after ElastAlert 2 has run over a time period ending in ``timestamp`` and should be used
to clear any state that may be obsolete as of ``timestamp``. ``timestamp`` is a datetime object.


Tutorial
--------

As an example, we are going to create a rule type for detecting suspicious logins. Let's imagine the data we are querying is login
events that contains IP address, username and a timestamp. Our configuration will take a list of usernames and a time range
and alert if a login occurs in the time range. First, let's create a modules folder in the base ElastAlert 2 folder:

.. code-block:: console

    $ mkdir elastalert_modules
    $ cd elastalert_modules
    $ touch __init__.py

Now, in a file named ``my_rules.py``, add

.. code-block:: python

    import dateutil.parser

    from elastalert.ruletypes import RuleType

    # elastalert.util includes useful utility functions
    # such as converting from timestamp to datetime obj
    from elastalert.util import ts_to_dt

    class AwesomeRule(RuleType):

        # By setting required_options to a set of strings
        # You can ensure that the rule config file specifies all
        # of the options. Otherwise, ElastAlert 2 will throw an exception
        # when trying to load the rule.
        required_options = set(['time_start', 'time_end', 'usernames'])

        # add_data will be called each time Elasticsearch is queried.
        # data is a list of documents from Elasticsearch, sorted by timestamp,
        # including all the fields that the config specifies with "include"
        def add_data(self, data):
            for document in data:

                # To access config options, use self.rules
                if document['username'] in self.rules['usernames']:

                    # Convert the timestamp to a time object
                    login_time = document['@timestamp'].time()

                    # Convert time_start and time_end to time objects
                    time_start = dateutil.parser.parse(self.rules['time_start']).time()
                    time_end = dateutil.parser.parse(self.rules['time_end']).time()

                    # If the time falls between start and end
                    if login_time > time_start and login_time < time_end:

                        # To add a match, use self.add_match
                        self.add_match(document)

        # The results of get_match_str will appear in the alert text
        def get_match_str(self, match):
            return "%s logged in between %s and %s" % (match['username'],
                                                       self.rules['time_start'],
                                                       self.rules['time_end'])

        # garbage_collect is called indicating that ElastAlert 2 has already been run up to timestamp
        # It is useful for knowing that there were no query results from Elasticsearch because
        # add_data will not be called with an empty list
        def garbage_collect(self, timestamp):
            pass


In the rule configuration file, ``examples/rules/example_login_rule.yaml``, we are going to specify this rule by writing

.. code-block:: yaml

    name: "Example login rule"
    es_host: elasticsearch.example.com
    es_port: 14900
    type: "elastalert_modules.my_rules.AwesomeRule"
    # Alert if admin, userXYZ or foobaz log in between 8 PM and midnight
    time_start: "20:00"
    time_end: "24:00"
    usernames:
    - "admin"
    - "userXYZ"
    - "foobaz"
    # We require the username field from documents
    include:
    - "username"
    alert:
    - debug

ElastAlert 2 will attempt to import the rule with ``from elastalert_modules.my_rules import AwesomeRule``.
This means that the folder must be in a location where it can be imported as a Python module.

An alert from this rule will look something like::

    Example login rule

    userXYZ logged in between 20:00 and 24:00

    @timestamp: 2015-03-02T22:23:24Z
    username: userXYZ
