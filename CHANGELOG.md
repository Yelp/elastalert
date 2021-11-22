# Template

## Breaking changes
- None

## New features
- TBD - [#000](https://github.com/jertel/elastalert2/pull/000) - @some_elastic_contributor_tbd

## Other changes
- None

# 2.x.x

## Breaking changes
- None

## New features
- None

## Other changes
- sphinx 4.2.0 to 4.3.0 and tzlocal==2.1 - [#561](https://github.com/jertel/elastalert2/pull/561) - @nsano-rururu
- jinja2 3.0.1 to 3.0.3 - [#562](https://github.com/jertel/elastalert2/pull/562) - @nsano-rururu
- Fix `get_rule_file_hash` TypeError - [#566](https://github.com/jertel/elastalert2/pull/566) - @JeffAshton

# 2.2.3

## Breaking changes
- None

## New features
- [Alertmanager] Added support for Alertmanager - [#503](https://github.com/jertel/elastalert2/pull/503) - @nsano-rururu
- Add summary_table_max_rows optional configuration to limit rows in summary tables - [#508](https://github.com/jertel/elastalert2/pull/508) - @mdavyt92
- Added support for shortening Kibana Discover URLs using Kibana Shorten URL API - [#512](https://github.com/jertel/elastalert2/pull/512) - @JeffAshton
- Added new alerter `HTTP Post 2` which allow more flexibility to build the body/headers of the request. - [#530](https://github.com/jertel/elastalert2/pull/530) - @lepouletsuisse
- [Slack] Added new option to include url to jira ticket if it is created in the same pipeline. - [#547](https://github.com/jertel/elastalert2/pull/547) - @hugefarsen
- Added support for multi ElasticSearch instances. - [#548](https://github.com/jertel/elastalert2/pull/548) - @buratinopy

## Other changes
- [Docs] Add exposed metrics documentation - [#498](https://github.com/jertel/elastalert2/pull/498) - @thisisxgp
- [Tests] Fix rules_test.py - [#499](https://github.com/jertel/elastalert2/pull/499) - @nsano-rururu
- Upgrade to Python 3.10 and Sphinx 4.2.0 - [#501](https://github.com/jertel/elastalert2/pull/501) - @jertel
- max_scrolling_count now has a default value of 990 to avoid stack overflow crashes - [#509](https://github.com/jertel/elastalert2/pull/509) - @jertel
- Update pytest 6.2.5, pytest-cov 3.0.0, pytest-xdist 2.4.0, pylint<2.12, tox 3.24.4 - [#511](https://github.com/jertel/elastalert2/pull/511) - @nsano-rururu
- Added a check on the value of the path "rules_folder" to make sure it exists - [#519](https://github.com/jertel/elastalert2/pull/519) - @AntoineBlaud
- [OpsGenie] Fix tags on subsequent alerts - [#537](https://github.com/jertel/elastalert2/pull/537) - @jertel

# 2.2.2

## Breaking changes
- None

## New features
- Added support for markdown style formatting of aggregation tables - [#415](https://github.com/jertel/elastalert2/pull/415) - @Neuro-HSOC
- [OpsGenie] Add support for custom description - [#457](https://github.com/jertel/elastalert2/pull/457), [#460](https://github.com/jertel/elastalert2/pull/460) - @nickbabkin
- [Tencent SMS] Added support for Tencent SMS - [#470](https://github.com/jertel/elastalert2/pull/470) - @liuxingjun
- Add support for Kibana 7.15 for Kibana Discover - [#481](https://github.com/jertel/elastalert2/pull/481) - @nsano-rururu
- Begin working toward support of OpenSearch (beta) [#483](https://github.com/jertel/elastalert2/pull/483) @nbrownus

## Other changes
- [Rule Test] Fix issue related to --start/--end/--days params - [#424](https://github.com/jertel/elastalert2/pull/424), [#433](https://github.com/jertel/elastalert2/pull/433) - @thican
- [TheHive] Reduce risk of sourceRef collision for Hive Alerts by using full UUID -[#513](https://github.com/jertel/elastalert2/pull/513) - @fwalloe
- Changed the wording of ElastAlert to ElastAlert 2 and Update FAQ -[#446](https://github.com/jertel/elastalert2/pull/446) - @nsano-rururu
- Add missing show_ssl_warn and silence_qk_value params to docs - [#469](https://github.com/jertel/elastalert2/pull/469) - @jertel
- [OpsGenie] Clarify documentation for URL endpoint to use in European region - [#475](https://github.com/jertel/elastalert2/pull/475) - @nsano-rururu
- [Docs] The documentation has been updated as the name of Amazon Elasticsearch Service has changed to Amazon OpenSearch Service. - [#478](https://github.com/jertel/elastalert2/pull/478) - @nsano-rururu
- [Tests] Improve test coverage of tencentsms.py - [#479](https://github.com/jertel/elastalert2/pull/479) - @liuxingjun
- [Docs] Tidy Exotel documentation - [#488](https://github.com/jertel/elastalert2/pull/488) - @ferozsalam

# 2.2.1

## Breaking changes
- None

## New features
- None

## Other changes
- Fixed typo in default setting accidentally introduced in [#407](https://github.com/jertel/elastalert2/pull/407) - [#413](https://github.com/jertel/elastalert2/pull/413) - @perceptron01

# 2.2.0

## Breaking changes
- [VictorOps] Changed `state_message` and `entity_display_name` values to be taken from an alert rule. - [#329](https://github.com/jertel/elastalert2/pull/329) - @ChristophShyper
  - Potentially a breaking change if the alert subject changes due to the new default behavior.
- Change metric/percentage rule types to store query_key as dict, instead of string, for consistency with other rule types. [#340](https://github.com/jertel/elastalert2/issues/340) - @AntoineBlaud

## New features
- [Kubernetes] Adding Image Pull Secret to Helm Chart - [#370](https://github.com/jertel/elastalert2/pull/370) - @robrankin
- Apply percentage_format_string to match_body percentage value; will appear in new percentage_formatted key - [#387](https://github.com/jertel/elastalert2/pull/387) - @iamxeph
- Add support for Kibana 7.14 for Kibana Discover - [#392](https://github.com/jertel/elastalert2/pull/392) - @nsano-rururu
- Add metric_format_string optional configuration for Metric Aggregation to format aggregated value - [#399](https://github.com/jertel/elastalert2/pull/399) - @iamxeph
- Make percentage_format_string support format() syntax in addition to old %-formatted syntax - [#403](https://github.com/jertel/elastalert2/pull/403) - @iamxeph
- Add custom_pretty_ts_format option to provides a way to define custom format of timestamps printed by pretty_ts() function - [#407](https://github.com/jertel/elastalert2/pull/407) - @perceptron01

## Other changes
- [Tests] Improve test code coverage - [#331](https://github.com/jertel/elastalert2/pull/331) - @nsano-rururu
- [Docs] Upgrade Sphinx from 4.0.2 to 4.1.2- [#332](https://github.com/jertel/elastalert2/pull/332) [#343](https://github.com/jertel/elastalert2/pull/343) [#344](https://github.com/jertel/elastalert2/pull/344) [#369](https://github.com/jertel/elastalert2/pull/369) - @nsano-rururu
- Ensure hit count returns correct value for newer ES clusters - [#333](https://github.com/jertel/elastalert2/pull/333) - @jeffashton
- [Tests] Upgrade Tox from 3.23.1 to 3.24.1 - [#345](https://github.com/jertel/elastalert2/pull/345) [#388](https://github.com/jertel/elastalert2/pull/388)  - @nsano-rururu
- Upgrade Jinja from 2.11.3 to 3.0.1 - [#350](https://github.com/jertel/elastalert2/pull/350) - @mrfroggg
- [Tests] Add test code. Changed ubuntu version of Dockerfile-test from latest to 21.10. - [#354](https://github.com/jertel/elastalert2/pull/354) - @nsano-rururu
- Remove Python 2.x compatibility code - [#354](https://github.com/jertel/elastalert2/pull/354) - @nsano-rururu
- [Docs] Added Chatwork proxy settings to documentation - [#360](https://github.com/jertel/elastalert2/pull/360) - @nsano-rururu
- Add settings to schema.yaml(Chatwork proxy, Dingtalk proxy) - [#361](https://github.com/jertel/elastalert2/pull/361) - @nsano-rururu
- [Docs] Tidy Twilio alerter documentation - [#363](https://github.com/jertel/elastalert2/pull/363) - @ferozsalam
- [Tests] Improved test coverage for opsgenie.py 96% to 100% - [#364](https://github.com/jertel/elastalert2/pull/364) - @nsano-rururu
- [Docs] Update mentions of JIRA to Jira - [#365](https://github.com/jertel/elastalert2/pull/365) - @ferozsalam
- [Docs] Tidy Datadog alerter documentation - [#380](https://github.com/jertel/elastalert2/pull/380) - @ferozsalam

# 2.1.2
## Breaking changes
- None

## New features
- [Rocket.Chat] Add support for generating Kibana Discover URLs to Rocket.Chat alerter - [#260](https://github.com/jertel/elastalert2/pull/260) - @nsano-rururu
- [Jinja] Provide rule key/values as possible Jinja data inputs - [#281](https://github.com/jertel/elastalert2/pull/281) - @mrfroggg
- [Kubernetes] Add securityContext and podSecurityContext to Helm chart - [#289](https://github.com/jertel/elastalert2/pull/289) - @lepouletsuisse
- [Rocket.Chat] Add options: rocket_chat_ca_certs, rocket_chat_ignore_ssl_errors, rocket_chat_timeout - [#302](https://github.com/jertel/elastalert2/pull/302) - @nsano-rururu
- [Jinja] Favor match keys over colliding rule keys when resolving Jinja vars; also add alert_text_jinja unit test - [#311](https://github.com/jertel/elastalert2/pull/311) - @mrfroggg
- [Opsgenie] Added possibility to specify source and entity attrs - [#315](https://github.com/jertel/elastalert2/pull/315) - @konstantin-kornienko
- [ServiceNow] Add support for `servicenow_impact` and `servicenow_urgency` parameters for ServiceNow alerter - [#316](https://github.com/jertel/elastalert2/pull/316) - @randolph-esnet
- [Jinja] Add Jinja support to alert_subject - [#318](https://github.com/jertel/elastalert2/pull/318) - @mrfroggg
@lepouletsuisse
- Metrics will now include time_taken, representing the execution duration of the rule - [#324](https://github.com/jertel/elastalert2/pull/324) - @JeffAshton

## Other changes
- [Prometheus] Continue fix for prometheus wrapper writeback function signature - [#256](https://github.com/jertel/elastalert2/pull/256) - @greut
- [Stomp] Improve exception handling in alerter - [#261](https://github.com/jertel/elastalert2/pull/261) - @nsano-rururu
- [AWS] Improve exception handling in Amazon SES and SNS alerters - [#264](https://github.com/jertel/elastalert2/pull/264) - @nsano-rururu
- [Docs] Clarify documentation for starting ElastAlert 2 - [#265](https://github.com/jertel/elastalert2/pull/265) - @ferozsalam
- Add exception handling for unsupported operand type - [#266](https://github.com/jertel/elastalert2/pull/266) - @nsano-rururu
- [Docs] Improve documentation for Python build requirements - [#267](https://github.com/jertel/elastalert2/pull/267) - @nsano-rururu
- [DataDog] Correct alerter logging - [#268](https://github.com/jertel/elastalert2/pull/268) - @nsano-rururu
- [Docs] Correct parameter code documentation for main ElastAlert runner - [#269](https://github.com/jertel/elastalert2/pull/269) - @ferozsalam
- [Command] alerter will now fail during init instead of during alert if given invalid command setting - [#270](https://github.com/jertel/elastalert2/pull/270) - @nsano-rururu
- [Docs] Consolidate all examples into a new examples/ sub folder - [#271](https://github.com/jertel/elastalert2/pull/271) - @ferozsalam
- [TheHive] Add example rule with Kibana Discover URL and query values in alert text - [#276](https://github.com/jertel/elastalert2/pull/276) - @markus-nclose
- Upgrade pytest-xdist from 2.2.1 to 2.3.0; clarify HTTPS support in docs; Add additional logging - [#283](https://github.com/jertel/elastalert2/pull/283) - @nsano-rururu
- [Tests] Add more alerter test coverage - [#284](https://github.com/jertel/elastalert2/pull/284) - @nsano-rururu
- [Tests] Improve structure and placement of test-related files in project tree - [#287](https://github.com/jertel/elastalert2/pull/287) - @ferozsalam
- Only attempt to adjust timezone if timezone is set to a non-empty string - [#288](https://github.com/jertel/elastalert2/pull/288) - @ferozsalam
- [Kubernetes] Deprecated `podSecurityPolicy` feature in Helm Chart as [it's deprecated in Kubernetes 1.21](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/) - [#289](https://github.com/jertel/elastalert2/pull/289) - @lepouletsuisse
- [Slack] Fix slack_channel_override schema - [#291](https://github.com/jertel/elastalert2/pull/291) - @JeffAshton
- [Rocket.Chat] Fix rocket_chat_channel_override schema - [#293](https://github.com/jertel/elastalert2/pull/293) - @nsano-rururu
- [Tests] Increase code coverage - [#294](https://github.com/jertel/elastalert2/pull/294) - @nsano-rururu
- [Docs] Added Kibana Discover sample - [#295](https://github.com/jertel/elastalert2/pull/295) - @nsano-rururu
- [AWS] Remove deprecated boto_profile setting - [#299](https://github.com/jertel/elastalert2/pull/299) - @nsano-rururu
- [Slack] Correct slack_alert_fields schema definition - [#300](https://github.com/jertel/elastalert2/pull/300) - @nsano-rururu
- [Tests] Correct code coverage to eliminate warnings - [#301](https://github.com/jertel/elastalert2/pull/301) - @nsano-rururu
- Eliminate unnecessary calls to Elasticsearch - [#303](https://github.com/jertel/elastalert2/pull/303) - @JeffAshton
- [Zabbix] Fix timezone parsing - [#304](https://github.com/jertel/elastalert2/pull/304) - @JeffAshton
- Improve logging of scheduler - [#305](https://github.com/jertel/elastalert2/pull/305) - @JeffAshton
- [Jinja] Update Jinja from 2.11.3 to 3.0.1; Improve handling of colliding variables - [#311](https://github.com/jertel/elastalert2/pull/311) - @mrfroggg
- [TheHive] Force observable artifacts to be strings - [#313](https://github.com/jertel/elastalert2/pull/313) - @pandvan
- Upgrade pylint from <2.9 to <2.10 - [#314](https://github.com/jertel/elastalert2/pull/314) - @nsano-rururu
- [ChatWork] Enforce character limit - [#319](https://github.com/jertel/elastalert2/pull/319) - @nsano-rururu
- [LineNotify] Enforce character limit - [#320](https://github.com/jertel/elastalert2/pull/320) - @nsano-rururu
- [Discord] Remove trailing backticks from alert body - [#321](https://github.com/jertel/elastalert2/pull/321) - @nsano-rururu
- Redirecting warnings to logging module - [#325](https://github.com/jertel/elastalert2/pull/325) - @JeffAshton

# 2.1.1

## Breaking changes
- None

## New features
- Add support for RocketChat - [#182](https://github.com/jertel/elastalert2/pull/182) - @nsano-rururu
- Expose rule scheduler properties as configurable settings - [#192](https://github.com/jertel/elastalert2/pull/192) - @jertel
- Exclude empty observables from TheHive requests - [#193](https://github.com/jertel/elastalert2/pull/193) - @LaZyDK
- Ensure TheHive tags are converted to strings before submitting TheHive request - [#206](https://github.com/jertel/elastalert2/pull/206) - @LaZyDK
- Add support for Elasticsearch API key authentication - [#208](https://github.com/jertel/elastalert2/pull/208) - @vbisserie
- Add support for Elasticsearch 7.13 for building Kibana Discover URLs - [#212](https://github.com/jertel/elastalert2/pull/212) - @nsano-rururu
- Follow symbolic links when traversing rules folder for rule files - [#214](https://github.com/jertel/elastalert2/pull/214) - @vbisserie
- Support optional suppression of SSL log warnings when http-posting alerts - [#222](https://github.com/jertel/elastalert2/pull/222) - @nsano-rururu
- Add support for inclusion of Kibana Discover URLs in MatterMost messages - [#239](https://github.com/jertel/elastalert2/pull/239) - @nsano-rururu
- Add support for inclusion of alert Title in MatterMost messages - [#246](https://github.com/jertel/elastalert2/pull/246) - @nsano-rururu

## Other changes
- Speed up unit tests by adding default parallelism - [#164](https://github.com/jertel/elastalert2/pull/164) - @ferozsalam
- Remove unused writeback_alias and fix --patience argument - [#167](https://github.com/jertel/elastalert2/pull/167) - @mrfroggg
- Fix Bearer token auth in initialisation script - [#169](https://github.com/jertel/elastalert2/pull/169) - @ferozsalam
- Finish refactoring alerters and tests into individual files - [#175, et al](https://github.com/jertel/elastalert2/pull/175) - @ferozsalam
- Improve HTTP POST alert documentation - [#178](https://github.com/jertel/elastalert2/pull/178) - @nsano-rururu
- Upgrade Sphinx from 3.5.4 to 4.0.2 - [#179](https://github.com/jertel/elastalert2/pull/179) - @nsano-rururu
- Fix Sphinx dependency version - [#181](https://github.com/jertel/elastalert2/pull/181) - @ferozsalam
- Switch to absolute imports - [#198](https://github.com/jertel/elastalert2/pull/198) - @ferozsalam
- Encode JSON output before writing test data - [#215](https://github.com/jertel/elastalert2/pull/215) - @vbisserie
- Update pytest from 6.0.0 to 6.2.4 - [#223](https://github.com/jertel/elastalert2/pull/223/files) - @nsano-rururu
- Ensure ChatWork alerter fails to initialize if missing required args - [#224](https://github.com/jertel/elastalert2/pull/224) - @nsano-rururu
- Ensure DataDog alerter fails to initialize if missing required args - [#225](https://github.com/jertel/elastalert2/pull/225) - @nsano-rururu
- Ensure DingTalk alerter fails to initialize if missing required args - [#226](https://github.com/jertel/elastalert2/pull/226) - @nsano-rururu
- Ensure Zabbix alerter fails to initialize if missing required args - [#227](https://github.com/jertel/elastalert2/pull/227) - @nsano-rururu
- MS Teams alerter no longer requires ms_teams_alert_summary arg - [#228](https://github.com/jertel/elastalert2/pull/228) - @nsano-rururu
- Improve Gitter alerter by explicitly specifying arg names  - [#230](https://github.com/jertel/elastalert2/pull/230) - @nsano-rururu
- Add more alerter test code coverage - [#231](https://github.com/jertel/elastalert2/pull/231) - @nsano-rururu
- Upgrade pytest-cov from 2.12.0 to 2.12.1 - [#232](https://github.com/jertel/elastalert2/pull/232) - @nsano-rururu
- Migrate away from external test mock dependency - [#233](https://github.com/jertel/elastalert2/pull/233) - @nsano-rururu
- Improve ElastAlert 2 documentation relating to running scenarios - [#234](https://github.com/jertel/elastalert2/pull/234) - @ferozsalam
- Improve test coverage and correct dict lookup syntax for alerter init functions - [#235](https://github.com/jertel/elastalert2/pull/235) - @nsano-rururu
- Fix schema bug with MatterMost alerts - [#239](https://github.com/jertel/elastalert2/pull/239) - @nsano-rururu
- Fix prometheus wrapper writeback function signature - [#253](https://github.com/jertel/elastalert2/pull/253) - @greut

# 2.1.0

## Breaking changes
- TheHive alerter refactoring - [#142](https://github.com/jertel/elastalert2/pull/142) - @ferozsalam  
  - See the updated documentation for changes required to alert formatting
- Dockerfile refactor for performance and size improvements - [#102](https://github.com/jertel/elastalert2/pull/102) - @jgregmac
	- Dockerfile base image changed from `python/alpine` to `python/slim-buster` to take advantage of pre-build python wheels, accelerate build times, and reduce image size. If you have customized an image, based on jertel/elastalert2, you may need to make adjustments.
	- Default base path changed to `/opt/elastalert` in the Dockerfile and in Helm charts. Update your volume binds accordingly.
	- Dockerfile now runs as a non-root user "elastalert". Ensure your volumes are accessible by this non-root user.
	- System packages removed from the Dockerfile: All dev packages, cargo, libmagic. Image size reduced to 250Mb.
	- `tmp` files and dev packages removed from the final container image.

## New features
- Support for multiple rules directories and fix `..data` Kubernetes/Openshift recursive directories in FileRulesLoader [#157](https://github.com/jertel/elastalert2/pull/157) - @mrfroggg
- Support environment variable substition in yaml files - [#149](https://github.com/jertel/elastalert2/pull/149) - @archfz
- Update schema.yaml and enhance documentation for Email alerter - [#144](https://github.com/jertel/elastalert2/pull/144) - @nsano-rururu 
- Default Email alerter to use port 25, and require http_post_url for HTTP Post alerter - [#143](https://github.com/jertel/elastalert2/pull/143) - @nsano-rururu
- Support extra message features for Slack and Mattermost - [#140](https://github.com/jertel/elastalert2/pull/140) - @nsano-rururu
- Support a footer in alert text - [#133](https://github.com/jertel/elastalert2/pull/133) - @nsano-rururu
- Added support for alerting via Amazon Simple Email System (SES) - [#105](https://github.com/jertel/elastalert2/pull/105) - @nsano-rururu

## Other changes
- Begin alerter refactoring to split large source code files into smaller files - [#161](https://github.com/jertel/elastalert2/pull/161) - @ferozsalam
- Update contribution guidelines with additional instructions for local testing - [#147](https://github.com/jertel/elastalert2/pull/147), [#148](https://github.com/jertel/elastalert2/pull/148) - @ferozsalam
- Add more unit test coverage - [#108](https://github.com/jertel/elastalert2/pull/108) - @nsano-rururu
- Update documentation: describe limit_execution, correct alerters list - [#107](https://github.com/jertel/elastalert2/pull/107) - @fberrez
- Fix issue with testing alerts that contain Jinja templates - [#101](https://github.com/jertel/elastalert2/pull/101) - @jertel
- Updated all references of Elastalert to use the mixed case ElastAlert, as that is the most prevalent formatting found in the documentation.

# 2.0.4

## Breaking changes
- None

## New features
- Update python-dateutil requirement from <2.7.0,>=2.6.0 to >=2.6.0,<2.9.0 - [#96](https://github.com/jertel/elastalert2/pull/96) - @nsano-rururu
- Update pylint requirement from <2.8 to <2.9 - [#95](https://github.com/jertel/elastalert2/pull/95) - @nsano-rururu
- Pin ES library to 7.0.0 due to upcoming newer library conflicts - [#90](https://github.com/jertel/elastalert2/pull/90) - @robrankin
- Re-introduce CHANGELOG.md to project - [#88](https://github.com/jertel/elastalert2/pull/88) - @ferozsalam
- Add option for suppressing TLS warnings - [#87](https://github.com/jertel/elastalert2/pull/87) - @alvarolmedo
- Add support for Twilio Copilot - [#86](https://github.com/jertel/elastalert2/pull/86) - @cdmastercom
- Support bearer token authentication with ES - [#85](https://github.com/jertel/elastalert2/pull/85) - @StribPav
- Add support for statsd metrics - [#83](https://github.com/jertel/elastalert2/pull/83) - @eladamitpxi
- Add support for multiple imports of rules via recursive import - [#83](https://github.com/jertel/elastalert2/pull/83) - @eladamitpxi
- Specify search size of 0 to improve efficiency of searches - [#82](https://github.com/jertel/elastalert2/pull/82) - @clyfish
- Add alert handler to create Datadog events - [#81](https://github.com/jertel/elastalert2/pull/81) - @3vanlock

## Other changes

- Added missing Helm chart config.yaml template file.
- Update .gitignore with more precise rule for /config.yaml file.
- Now publishing container images to both DockerHub and to GitHub Packages for redundancy.
- Container images are now built and published via GitHub actions instead of relying on DockerHub's automated builds.
- Update PIP library description and Helm chart description to be consistent.
- Continue updates to change references from _ElastAlert_ to _ElastAlert 2_
