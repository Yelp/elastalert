# Fork of yelp/elastalert

The original [yelp/elastalert][0] repository has become mostly stale, with hundreds of open PRs and
over 1000 open issues. The Yelp team has acknowledged that they are winding down support of
Elastalert. Consequently, it is difficult to merge fixes, dependency upgrades, and new features into
Elastalert. Because of this, a fork of Elastalert has been created. [jertel/elastalert][1] will be
an alternate repository for updates, until a new maintainer is appointed by the Yelp team and it's
clear that the new maintainers are responding to PRs and issues. 

## Documentation

Updated Elastalert documentation that reflects the state of the _alt_ branch can be found [here][3].
This is the place to start if you're not familiar with Elastalert at all.

The full list of platforms that Elastalert can fire alerts into can be found [here][4]

The original README for Elastalert can be found [here][5]. Please note that this file is
not being actively maintained, and will probably grow less accurate over time.

## Contributing

PRs are welcome, but must include tests, when possible. PRs will not be merged if they do not pass
the automated CI workflows. 

The current status of the _alt_ branch CI workflow:

![CI Workflow](https://github.com/jertel/elastalert/workflows/alt_build_test/badge.svg)

## Docker

If you're interested in a pre-built Docker image for either the official yelp/elastalert release, or
for this fork, check out the [elastalert-docker][2] project on Docker Hub.

## License

Elastalert is licensed under the [Apache License, Version 2.0][6].

[0]: https://github.com/yelp/elastalert
[1]: https://github.com/jertel/elastalert 
[2]: https://hub.docker.com/r/jertel/elastalert-docker
[3]: https://elastalert2.readthedocs.io/
[4]: https://elastalert2.readthedocs.io/en/latest/ruletypes.html#alerts
[5]: https://github.com/jertel/elastalert/blob/alt/README-old.md
[6]: http://www.apache.org/licenses/LICENSE-2
