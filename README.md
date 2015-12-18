[![Stories in Ready](https://badge.waffle.io/Yelp/elastalert.png?label=ready&title=Ready)](https://waffle.io/Yelp/elastalert)
[![Stories in In Progress](https://badge.waffle.io/Yelp/elastalert.png?label=in%20progress&title=In%20Progress)](https://waffle.io/Yelp/elastalert)
[![Build Status](https://travis-ci.org/Yelp/elastalert.svg)](https://travis-ci.org/Yelp/elastalert)
[![Join the chat at https://gitter.im/Yelp/elastalert](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/Yelp/elastalert?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## ElastAlert - [Read the Docs](http://elastalert.readthedocs.org).
### Easy & Flexible Alerting With ElasticSearch

ElastAlert is a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch.

At Yelp, we use Elasticsearch, Logstash and Kibana for managing our ever increasing amount of data and logs.
Kibana is great for visualizing and querying data, but we quickly realized that it needed a companion tool for alerting
on inconsistencies in our data. Out of this need, ElastAlert was created.

If you have data being written into Elasticsearch in near real time and want to be alerted when that data matches certain patterns, ElastAlert is the tool for you. If you can see it in Kibana, ElastAlert can alert on it.

## Overview

We designed ElastAlert to be reliable, highly modular, and easy to set up and configure.

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
- "Match when a never before seen term appears in a field" (``new_term`` type)
- "Match when the number of unique values for a field is above or below a threshold (``cardinality`` type)

Currently, we have support built in for the following alert types:

- Email
- JIRA
- OpsGenie
- Commands
- HipChat
- Slack
- AWS SNS
- VictorOps
- PagerDuty

Additional rule types and alerts can be easily imported or written.

In addition to this basic usage, there are many other features that make alerts more useful:

- Alerts link to Kibana dashboards
- Aggregate counts for arbitrary fields
- Combine alerts into periodic reports
- Separate alerts by using a unique key field
- Intercept and enhance match data

To get started, check out `Running ElastAlert For The First Time` in the [documentation](http://elastalert.readthedocs.org).

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

Read the documentation at [Read the Docs](http://elastalert.readthedocs.org).

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

- ``example_new_term.yaml`` is an example of the "new term" rule type, which alerts when a new value appears in a field or fields. In this example,
an email is sent when a new value of ("username", "computer") is encountered in example login logs.

## License

ElastAlert is licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0

### Read the documentation at [Read the Docs](http://elastalert.readthedocs.org).

### Questions? Drop by #elastalert on Freenode IRC.
