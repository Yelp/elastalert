# ElastAlert

A framework for alerting out of Elasticsearch. You should use ElastAlert if you have data being indexed into Elasticsearch in near real time and would like
to take action when that data matches certain patterns.

## About

ElastAlert is a generic alerting framework for querying, processing and alerting on data in Elasticsearch.
It takes a set of rules, periodically queries Elasticsearch, and runs the rules against the data.
Each rule is defined in a yaml file, which specifies the rule type, Elasticsearch filters, and alerts.

## Running ElastAlert

``$ python elastalert/elastalert.py [--debug] [--verbose] [--start <timestamp>] [--end <timestamp>] [--rule <filename.yaml>] [--config <filename.yaml>]``

``--debug`` will print additional information to the screen as well as suppresses alerts and instead prints the alert body.

``--verbose`` will print additional information without without supressing alerts.

``--start`` will begin querying at the given timestamp. By default, ElastAlert will begin querying from the present.
Timestamp format is ``YYYY-MM-DDTHH-MM-SS[-/+HH:MM]`` (Note the T between date and hour).
Eg: ``--start 2014-09-26T12:00:00`` (UTC) or ``--start 2014-10-01T07:30:00-05:00``

``--end`` will cause ElastAlert to stop querying at the given timestamp. By default, ElastAlert will continue
to query indefinitely.

``--rule`` will allow you to run only one rule. It must still be in the rules folder.
Eg: ``--rule this_rule.yaml``

``--config`` allows you to specify the location of the configuration. By default, it is will look for config.yaml in the current directory.

## Documentation

Documentation is located in the docs/ folder. Several styles can be built using the makefile in docs/.
```
$ cd docs/
$ make html
```

## Configuration

See config.yaml.example for details on configuration.

## Example rules

Examples of different types of rules can be found in example_rules/.

- ``example_spike.yaml`` is an example of the "spike" rule type, which allows you to alert when the rate of events, averaged over a time period,
increases by a given factor. This example will send an email alert when there are 3 times more events matching a filter occurring within the
last 2 hours than the number of events in the previous 2 hours.

- ``example_frequency.yaml`` is an example of the "frequency" rule type, which will alert when there are a given number of events occuring
within a time period. This example will send an email when 50 documents matching a given filter occur within a 4 hour timeframe.

- ``example_change.yaml`` is an example of the "change" rule type, which will alert when a certain field in two documents changes. In this example,
the alert email is sent when two documents with the same 'username' field but a different value of the 'country_name' field occur within 24 hours
of each other.
