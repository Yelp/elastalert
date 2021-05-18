# Template

## Breaking changes
- None

## New features
- TBD - [#000](https://github.com/jertel/elastalert2/pull/000) - @some_elastic_contributor_tbd

## Other changes
- None

# Unreleased

## Breaking changes
- None

## New features
- None

## Other changes
- Speed up unit tests by adding default parallelism - [164](https://github.com/jertel/elastalert2/pull/164) - @ferozsalam

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
