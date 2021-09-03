.. _writingalerts:

Adding a New Alerter
====================

Alerters are subclasses of ``Alerter``, found in ``elastalert/alerts.py``. They are given matches
and perform some action based on that. Your alerter needs to implement two member functions, and will look
something like this:

.. code-block:: python

    class AwesomeNewAlerter(Alerter):
        required_options = set(['some_config_option'])
        def alert(self, matches):
            ...
        def get_info(self):
            ...

You can import alert types by specifying the type as ``module.file.AlertName``, where module is the name of a python module,
and file is the name of the python file containing a ``Alerter`` subclass named ``AlertName``.

Basics
------

The alerter class will be instantiated when ElastAlert 2 starts, and be periodically passed
matches through the ``alert`` method. ElastAlert 2 also writes back info about the alert into
Elasticsearch that it obtains through ``get_info``. Several important member properties:

``self.required_options``: This is a set containing names of configuration options that must be
present. ElastAlert 2 will not instantiate the alert if any are missing.

``self.rule``: The dictionary containing the rule configuration. All options specific to the alert
should be in the rule configuration file and can be accessed here.

``self.pipeline``: This is a dictionary object that serves to transfer information between alerts. When an alert is triggered,
a new empty pipeline object will be created and each alerter can add or receive information from it. Note that alerters
are called in the order they are defined in the rule file. For example, the Jira alerter will add its ticket number
to the pipeline and the email alerter will add that link if it's present in the pipeline.

alert(self, match):
-------------------

ElastAlert 2 will call this function to send an alert. ``matches`` is a list of dictionary objects with
information about the match. You can get a nice string representation of the match by calling
``self.rule['type'].get_match_str(match, self.rule)``. If this method raises an exception, it will
be caught by ElastAlert 2 and the alert will be marked as unsent and saved for later.

get_info(self):
---------------

This function is called to get information about the alert to save back to Elasticsearch. It should
return a dictionary, which is uploaded directly to Elasticsearch, and should contain useful information
about the alert such as the type, recipients, parameters, etc.

Tutorial
--------

Let's create a new alert that will write alerts to a local output file. First,
create a modules folder in the base ElastAlert 2 folder:

.. code-block:: console

    $ mkdir elastalert_modules
    $ cd elastalert_modules
    $ touch __init__.py

Now, in a file named ``my_alerts.py``, add

.. code-block:: python

    from elastalert.alerts import Alerter, BasicMatchString

    class AwesomeNewAlerter(Alerter):

        # By setting required_options to a set of strings
        # You can ensure that the rule config file specifies all
        # of the options. Otherwise, ElastAlert 2 will throw an exception
        # when trying to load the rule.
        required_options = set(['output_file_path'])

        # Alert is called
        def alert(self, matches):

            # Matches is a list of match dictionaries.
            # It contains more than one match when the alert has
            # the aggregation option set
            for match in matches:

                # Config options can be accessed with self.rule
                with open(self.rule['output_file_path'], "a") as output_file:

                    # basic_match_string will transform the match into the default
                    # human readable string format
                    match_string = str(BasicMatchString(self.rule, match))

                    output_file.write(match_string)

        # get_info is called after an alert is sent to get data that is written back
        # to Elasticsearch in the field "alert_info"
        # It should return a dict of information relevant to what the alert does
        def get_info(self):
            return {'type': 'Awesome Alerter',
                    'output_file': self.rule['output_file_path']}


In the rule configuration file, we are going to specify the alert by writing

.. code-block:: yaml

    alert: "elastalert_modules.my_alerts.AwesomeNewAlerter"
    output_file_path: "/tmp/alerts.log"

ElastAlert  2 will attempt to import the alert with ``from elastalert_modules.my_alerts import AwesomeNewAlerter``.
This means that the folder must be in a location where it can be imported as a python module.
