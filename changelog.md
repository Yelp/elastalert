# Change Log

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
