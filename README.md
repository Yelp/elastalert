# Elastalert 2

Elastalert 2 is the supported fork of [Elastalert][0], which had been maintained by the Yelp team
but become mostly stale when the Yelp team ceased using Elastalert. 

Elastalert 2 is backwards compatible with the original Elastalert rules.

## Documentation

Documentation, including an FAQ, for Elastalert 2 can be found on [readthedocs.com][3]. This is the place to start if you're not familiar with Elastalert at all.

The full list of platforms that Elastalert can fire alerts into can be found [in the documentation][4].


## Contributing

PRs are welcome, but must include tests, when possible. PRs will not be merged if they do not pass
the automated CI workflows. 

The current status of the CI workflow:

![CI Workflow](https://github.com/jertel/elastalert/workflows/master_build_test/badge.svg)

## Docker

If you're interested in a pre-built Docker image check out the [elastalert2][2] project on Docker Hub.

A properly configured elastalert_config.json file must be mounted into the container during startup of the container. Use the [example file][1] provided as a template, and once saved locally to a file such as `/tmp/elastalert.yaml`, run the container as follows:

```bash
docker run -d -v /tmp/elastalert.yaml:/opt/config/elastalert_config.yaml jertel/elastalert2
```

To build the image locally, install Docker and then run the following command:
```
docker build . -t elastalert
```

## Kubernetes

See the Helm chart [README.md](chart/elastalert2/README.md) for information on installing this application into an existing Kubernetes cluster.

## License

Elastalert is licensed under the [Apache License, Version 2.0][5].

[0]: https://github.com/yelp/elastalert
[1]: https://github.com/jertel/elastalert2/blob/master/config.yaml.example
[2]: https://hub.docker.com/r/jertel/elastalert2
[3]: https://elastalert2.readthedocs.io/
[4]: https://elastalert2.readthedocs.io/en/latest/ruletypes.html#alerts
[5]: http://www.apache.org/licenses/LICENSE-2

