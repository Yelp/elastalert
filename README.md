# Elastalert 2

Elastalert 2 is the supported fork of [Elastalert][0], which had been maintained by the Yelp team
but become mostly stale when the Yelp team ceased using Elastalert.

Elastalert 2 is backwards compatible with the original Elastalert rules.

![CI Workflow](https://github.com/jertel/elastalert/workflows/master_build_test/badge.svg)

## Documentation

Documentation, including an FAQ, for Elastalert 2 can be found on [readthedocs.com][3]. This is the place to start if you're not familiar with Elastalert at all.

The full list of platforms that Elastalert can fire alerts into can be found [in the documentation][4].

## Contributing

Please see our [contributing guidelines][6].

## Docker

If you're interested in a pre-built Docker image check out the [elastalert2][2] project on Docker Hub.

Be aware that the `latest` tag of the image represents the latest commit into the master branch. If you prefer to upgrade more slowly you will need utilize a versioned tag, such as `2.0.4` instead, or `2` if you are comfortable with always using the latest released version of Elastalert2.

A properly configured config.yaml file must be mounted into the container during startup of the container. Use the [example file][1] provided as a template, and once saved locally to a file such as `/tmp/elastalert.yaml`, run the container as follows:

```bash
docker run -d -v /tmp/elastalert.yaml:/opt/elastalert/config.yaml jertel/elastalert2
```

To build the image locally, install Docker and then run the following command:

```bash
docker build . -t elastalert
```

## Kubernetes

See the Helm chart [README.md][7] for information on installing this application into an existing Kubernetes cluster.

## License

Elastalert 2 is licensed under the [Apache License, Version 2.0][5].

[0]: https://github.com/yelp/elastalert
[1]: https://github.com/jertel/elastalert2/blob/master/config.yaml.example
[2]: https://hub.docker.com/r/jertel/elastalert2
[3]: https://elastalert2.readthedocs.io/
[4]: https://elastalert2.readthedocs.io/en/latest/ruletypes.html#alerts
[5]: https://www.apache.org/licenses/LICENSE-2.0
[6]: https://github.com/jertel/elastalert2/blob/master/CONTRIBUTING.md
[7]: https://github.com/jertel/elastalert2/chart/elastalert2/README.md