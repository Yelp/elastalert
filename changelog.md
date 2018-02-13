# Change Log

## v0.1.29

###
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
