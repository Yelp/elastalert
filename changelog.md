# Change Log

# v0.2.4

### Added
- Added back customFields support for The Hive

# v0.2.3

### Added
- Added back TheHive alerter without TheHive4py library

# v0.2.2

### Added
- Integration with Kibana Discover app
- Addied ability to specify opsgenie alert details 

### Fixed
- Fix some encoding issues with command alerter
- Better error messages for missing config file
- Fixed an issue with run_every not applying per-rule
- Fixed an issue with rules not being removed
- Fixed an issue with top count keys and nested query keys
- Various documentation fixes
- Fixed an issue with not being able to use spike aggregation

### Removed
- Remove The Hive alerter

# v0.2.1

### Fixed
- Fixed an AttributeError introduced in 0.2.0

# v0.2.0

- Switched to Python 3

### Added
- Add rule loader class for customized rule loading
- Added thread based rules and limit_execution
- Run_every can now be customized per rule

### Fixed
- Various small fixes

# v0.1.39

### Added
- Added spike alerts for metric aggregations
- Allow SSL connections for Stomp
- Allow limits on alert text length
- Add optional min doc count for terms queries
- Add ability to index into arrays for alert_text_args, etc

### Fixed
- Fixed bug involving --config flag with create-index
- Fixed some settings not being inherited from the config properly
- Some fixes for Hive alerter
- Close SMTP connections properly
- Fix timestamps in Pagerduty v2 payload
- Fixed an bug causing aggregated alerts to mix up

# v0.1.38

### Added
- Added PagerTree alerter
- Added Line alerter
- Added more customizable logging
- Added new logic in test-rule to detemine the default timeframe

### Fixed
- Fixed an issue causing buffer_time to sometimes be ignored

# v0.1.37

### Added
- Added more options for Opsgenie alerter
- Added more pagerduty options
- Added ability to add metadata to elastalert logs

### Fixed
- Fixed some documentation to be more clear
- Stop requiring doc_type for metric aggregations
- No longer puts quotes around regex terms in blacklists or whitelists

# v0.1.36

### Added
- Added a prefix "metric_" to the key used for metric aggregations to avoid possible conflicts
- Added option to skip Alerta certificate validation

### Fixed
- Fixed a typo in the documentation for spike rule

# v0.1.35

### Fixed
- Fixed an issue preventing new term rule from working with terms query

# v0.1.34

### Added
- Added prefix/suffix support for summary table
- Added support for ignoring SSL validation in Slack
- More visible exceptions during query parse failures

### Fixed
- Fixed top_count_keys when using compound query_key
- Fixed num_hits sometimes being reported too low
- Fixed an issue with setting ES_USERNAME via env
- Fixed an issue when using test script with custom timestamps
- Fixed a unicode error when using Telegram
- Fixed an issue with jsonschema version conflict
- Fixed an issue with nested timestamps in cardinality type

# v0.1.33

### Added
- Added ability to pipe alert text to a command
- Add --start and --end support for elastalert-test-rule
- Added ability to turn blacklist/whitelist files into queries for better performance
- Allow setting of OpsGenie priority
- Add ability to query the adjacent index if timestamp_field not used for index timestamping
- Add support for pagerduty v2
- Add option to turn off .raw/.keyword field postfixing in new term rule
- Added --use-downloaded feature for elastalert-test-rule

### Fixed
- Fixed a bug that caused num_hits in matches to sometimes be erroneously small
- Fixed an issue with HTTP Post alerter that could cause it to hang indefinitely
- Fixed some issues with string formatting for various alerters
- Fixed a couple of incorrect parts of the documentation

# v0.1.32

### Added
- Add support for setting ES url prefix via environment var
- Add support for using native Slack fields in alerts

### Fixed
- Fixed a bug that would could scrolling queries to sometimes terminate early

# v0.1.31

### Added
- Added ability to add start date to new term rule

### Fixed
- Fixed a bug in create_index which would try to delete a nonexistent index
- Apply filters to new term rule all terms query
- Support Elasticsearch 6 for new term rule
- Fixed is_enabled not working on rule changes


# v0.1.30

### Added
- Alerta alerter
- Added support for transitioning JIRA issues
- Option to recreate index in elastalert-create-index

### Fixed
- Update jira_ custom fields before each alert if they were modified
- Use json instead of simplejson
- Allow for relative path for smtp_auth_file
- Fixed some grammar issues
- Better code formatting of index mappings
- Better formatting and size limit for HipChat HTML
- Fixed gif link in readme for kibana plugin
- Fixed elastalert-test-rule with Elasticsearch > 4
- Added documentation for is_enabled option

## v0.1.29

### Added
- Added a feature forget_keys to prevent realerting when using flatline with query_key
- Added a new alert_text_type, aggregation_summary_only

### Fixed
- Fixed incorrect documentation about es_conn_timeout default

## v0.1.28

### Added
- Added support for Stride formatting of simple HTML tags
- Added support for custom titles in Opsgenie alerts
- Added a denominator to percentage match based alerts

### Fixed
- Fixed a bug with Stomp alerter connections
- Removed escaping of some characaters in Slack messages

## v0.1.27

# Added
- Added support for a value other than <MISSING VALUE> in formatted alerts

### Fixed
- Fixed a failed creation of elastalert indicies when using Elasticsearch 6
- Truncate Telegram alerts to avoid API errors

## v0.1.26

### Added
- Added support for Elasticsearch 6
- Added support for mentions in Hipchat

### Fixed
- Fixed an issue where a nested field lookup would crash if one of the intermediate fields was null

## v0.1.25

### Fixed
- Fixed a bug causing new term rule to break unless you passed a start time
- Add a slight clarification on the localhost:9200 reported in es_debug_trace

## v0.1.24

### Fixed
- Pinned pytest
- create-index reads index name from config.yaml
- top_count_keys now works for context on a flatline rule type
- Fixed JIRA behavior for issues with statuses that have spaces in the name

## v0.1.22

### Added
- Added Stride alerter
- Allow custom string formatters for aggregation percentage
- Added a field to disable rules from config
- Added support for subaggregations for the metric rule type

### Fixed
- Fixed a bug causing create-index to fail if missing config.yaml
- Fixed a bug when using ES5 with query_key and top_count_keys
- Allow enhancements to set and clear arbitrary JIRA fields
- Fixed a bug causing timestamps to be formatted in scientific notation
- Stop attempting to initialize alerters in debug mode
- Changed default alert ordering so that JIRA tickets end up in other alerts
- Fixed a bug when using Stomp alerter with complex query_key
- Fixed a bug preventing hipchat room ID from being an integer
- Fixed a bug causing duplicate alerts when using spike with alert_on_new_data
- Minor fixes to summary table formatting
- Fixed elastalert-test-rule when using new term rule type

## v0.1.21

### Fixed
- Fixed an incomplete bug fix for preventing duplicate enhancement runs

## v0.1.20

### Added
- Added support for client TLS keys

### Fixed
- Fixed the formatting of summary tables in Slack
- Fixed ES_USE_SSL env variable
- Fixed the unique value count printed by new_term rule type
- Jira alerter no longer uses the non-existent json code formatter

## v0.1.19

### Added
- Added support for populating JIRA fields via fields in the match
- Added support for using a TLS certificate file for SMTP connections
- Allow a custom suffix for non-analyzed Elasticsearch fields, like ".raw" or ".keyword"
- Added match_time to Elastalert alert documents in Elasticsearch

### Fixed
- Fixed an error in the documentation for rule importing
- Prevent enhancements from re-running on retried alerts
- Fixed a bug when using custom timestamp formats and new term rule
- Lowered jira_bump_after_inactivity default to 0 days

## v0.1.18

### Added
- Added a new alerter "post" based on "simple" which makes POSTS JSON to HTTP endpoints
- Added an option jira_bump_after_inacitivty to prevent ElastAlert commenting on active JIRA tickets

### Removed
- Removed "simple" alerter, replaced by "post"

## v0.1.17

### Added
- Added a --patience flag to allow Elastalert to wait for Elasticsearch to become available
- Allow custom PagerDuty alert titles via alert_subject

## v0.1.16

### Fixed
- Fixed a bug where JIRA titles might not use query_key values
- Fixed a bug where flatline alerts don't respect query_key for realert
- Fixed a typo "twilio_accout_sid"

### Added
- Added support for env variables in kibana4 dashboard links
- Added ca_certs option for custom CA support

## v0.1.15

### Fixed
- Fixed a bug where Elastalert would crash on connection error during startup
- Fixed some typos in documentation
- Fixed a bug in metric bucket offset calculation
- Fixed a TypeError in Service Now alerter

### Added
- Added support for compound compare key in change rules
- Added support for absolute paths in rule config imports
- Added Microsoft Teams alerter
- Added support for markdown in Slack alerts
- Added error codes to test script
- Added support for lists in email_from_field


## v0.1.14 - 2017-05-11

### Fixed
- Twilio alerter uses the from number appropriately
- Fixed a TypeError in SNS alerter
- Some changes to requirements.txt and setup.py
- Fixed a TypeError in new term rule

### Added
- Set a custom pagerduty incident key
- Preserve traceback in most exceptions

## v0.1.12 - 2017-04-21

### Fixed
- Fixed a bug causing filters to be ignored when using Elasticsearch 5


## v0.1.11 - 2017-04-19

### Fixed
- Fixed an issue that would cause filters starting with "query" to sometimes throw errors in ES5
- Fixed a bug with multiple versions of ES on different rules
- Fixed a possible KeyError when using use_terms_query with ES5

## v0.1.10 - 2017-04-17

### Fixed
- Fixed an AttributeError occuring with older versions of Elasticsearch library
- Made example rules more consistent and with unique names
- Fixed an error caused by a typo when es_username is used

## v0.1.9 - 2017-04-14

### Added
- Added a changelog
- Added metric aggregation rule type
- Added percentage match rule type
- Added default doc style and improved the instructions
- Rule names will default to the filename
- Added import keyword in rules to include sections from other files
- Added email_from_field option to derive the recipient from a field in the match
- Added simple HTTP alerter
- Added Exotel SMS alerter
- Added a readme link to third party Kibana plugin
- Added option to use env variables to configure some settings
- Added duplicate hits count in log line

### Fixed
- Fixed a bug in change rule where a boolean false would be ignored
- Clarify documentation on format of alert_text_args and alert_text_kw
- Fixed a bug preventing new silence stashes from being loaded after a rule has previous alerted
- Changed the default es_host in elastalert-test-rule to localhost
- Fixed a bug preventing ES <5.0 formatted queries working in elastalert-test-rule
- Fixed top_count_keys adding .raw on ES >5.0, uses .keyword instead
- Fixed a bug causing compound aggregation keys not to work
- Better error reporting for the Jira alerter
- AWS request signing now refreshes credentials, uses boto3
- Support multiple ES versions on different rules
- Added documentation for percentage match rule type

### Removed
- Removed a feature that would disable writeback_es on errors, causing various issues
