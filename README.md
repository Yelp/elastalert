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

## Releases

As Elastalert 2 is a community-maintained project, releases will typically contain unrelated contributions without a common theme. It's up to the maintainers to determine when the project is ready for a release, however, if you are looking to use a newly merged feature that hasn't yet been released, feel free to open a [discussion][6] and let us know.

Maintainers, when creating a new release, follow the procedure below:

1. Determine an appropriate new version number in the format _a.b.c_, using the following guidelines:
	- The major version (a) should not change.
	- The minor version (b) should be incremented if a new feature has been added or if a bug fix will have a significant user-impact. Reset the patch version to zero if the minor version is incremented.
	- The patch version (c) should be incremented when low-impact bugs are fixed, or security vulnerabilities are patched.
2. Ensure the following are updated _before_ publishing/tagging the new release:
	- [setup.py](setup.py): Match the version to the new release version
	- [Chart.yaml](chart/elastalert2/Chart.yaml): Match chart version and the app version to the new release version (typically keep them in sync)
	- [values.yaml](chart/elastalert2/values.yaml): Match the default image version to the new release version.
	- [README.md](chart/elastalert2/README.md): Match the default image version to the new release version.
3. Double-check that the Docker image successfully built the latest image.
4. Create a [new][7] release.
	- The title (and tag) of the release will be the same value as the new version determined in step 1.
	- The description of the release will contain a bulleted list of all merged pull requests, in the following format:
		`- PR/commit message #000 - @committer`
	- Check the box to 'Create a discussion for this release'.
	- Save the draft.
5. Wait a minimum of a few hours for community feedback in case someone notices a problem with the the upcoming release.
6. Publish the release.

## License

Elastalert is licensed under the [Apache License, Version 2.0][5].

[0]: https://github.com/yelp/elastalert
[1]: https://github.com/jertel/elastalert2/blob/master/config.yaml.example
[2]: https://hub.docker.com/r/jertel/elastalert2
[3]: https://elastalert2.readthedocs.io/
[4]: https://elastalert2.readthedocs.io/en/latest/ruletypes.html#alerts
[5]: http://www.apache.org/licenses/LICENSE-2
[6]: https://github.com/jertel/elastalert2/discussions
[7]: https://github.com/jertel/elastalert2/releases/new