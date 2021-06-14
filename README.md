# ElastAlert 2

ElastAlert 2 is the supported fork of [ElastAlert][0], which had been maintained by the Yelp team
but become mostly stale when the Yelp team ceased using ElastAlert.

ElastAlert 2 is backwards compatible with the original ElastAlert rules.

![CI Workflow](https://github.com/jertel/elastalert/workflows/master_build_test/badge.svg)

## Docker and Kubernetes

ElastAlert 2 is well-suited to being run as a microservice, and is available
as a [Docker container][2]. For more instructions on how to
configure and run ElastAlert 2 using Docker, see [here][8].

A [Helm chart][7] is also included for easy configuration as a Kubernetes deployment. 

## Documentation

Documentation, including an FAQ, for ElastAlert 2 can be found on [readthedocs.com][3]. This is the place to start if you're not familiar with ElastAlert 2 at all.

The full list of platforms that ElastAlert 2 can fire alerts into can be found [in the documentation][4].

## Contributing

Please see our [contributing guidelines][6].

## License

ElastAlert 2 is licensed under the [Apache License, Version 2.0][5].

[0]: https://github.com/yelp/elastalert
[1]: https://github.com/jertel/elastalert2/blob/master/examples/config.yaml.example
[2]: https://hub.docker.com/r/jertel/elastalert2
[3]: https://elastalert2.readthedocs.io/
[4]: https://elastalert2.readthedocs.io/en/latest/ruletypes.html#alerts
[5]: https://www.apache.org/licenses/LICENSE-2.0
[6]: https://github.com/jertel/elastalert2/blob/master/CONTRIBUTING.md
[7]: https://github.com/jertel/elastalert2/tree/master/chart/elastalert2
[8]: https://elastalert2.readthedocs.io/en/latest/running_elastalert.html
