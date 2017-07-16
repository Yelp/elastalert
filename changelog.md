# Change Log

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
