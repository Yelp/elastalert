# Elastalert 2

Elastalert 2 is the supported fork of [Elastalert][0], which had been maintained by the Yelp team
but become mostly stale when the Yelp team ceased using Elastalert. 

Elastalert 2 is backwards compatible with the original Elastalert rules.

## Documentation

Documentation for Elastalert 2 can be found on [readthedocs.com][3]. This is the place to start if you're not familiar with Elastalert at all.

The full list of platforms that Elastalert can fire alerts into can be found [in the documentation][4].

The original README for Elastalert can be found [here][5]. Please note that this file is
not being actively maintained, and will probably grow less accurate over time.

## Contributing

PRs are welcome, but must include tests, when possible. PRs will not be merged if they do not pass
the automated CI workflows. 

The current status of the CI workflow:

![CI Workflow](https://github.com/jertel/elastalert/workflows/master_build_test/badge.svg)

## Docker

If you're interested in a pre-built Docker image for either the official yelp/elastalert release, or
for this fork, check out the [elastalert2][2] project on Docker Hub.

## License

Elastalert is licensed under the [Apache License, Version 2.0][6].

[0]: https://github.com/yelp/elastalert
[1]: https://github.com/jertel/elastalert 
[2]: https://hub.docker.com/r/jertel/elastalert2
[3]: https://elastalert2.readthedocs.io/
[4]: https://elastalert2.readthedocs.io/en/latest/ruletypes.html#alerts
[5]: https://github.com/jertel/elastalert/blob/alt/README-old.md
[6]: http://www.apache.org/licenses/LICENSE-2
