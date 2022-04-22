# Contributing to ElastAlert 2

## Guidelines

PRs are welcome, but must include tests, when possible. PRs will not be merged if they do not pass
the automated CI workflows. To test your changes before creating a PR, run
`sudo make clean; sudo make test-docker` from the root of the repository (requires Docker to be
running on your machine).

Make sure you follow the existing coding style from the existing codebase. Do not reformatting the existing code to fit your own personal style.

Before submitting the PR review that you have included the following changes, where applicable:
- Documentation: If you're adding new functionality, any new configuration options should be documented appropriately in the docs/ folder.
- Helm Chart: If your new feature introduces settings consider adding those to the Helm chart [README.md](chart/elastalert2/README.md) and [values.yaml](chart/elastalert2/values.yaml)
- Examples: If your new feature includes new configuration options, review the [Example config file](examples/config.yaml.example) to see if they should be added there for consistency with other configuration options.
- Change log: Describe your contribution to the appropriate section(s) for the _Upcoming release_, in the [CHANGELOG.md](CHANGELOG.md) file.

## Releases

STOP - DO NOT PROCEED! This section is only applicable to project administrators. PR _contributors_ do not need to follow the below procedure.

As ElastAlert 2 is a community-maintained project, releases will typically contain unrelated contributions without a common theme. It's up to the maintainers to determine when the project is ready for a release, however, if you are looking to use a newly merged feature that hasn't yet been released, feel free to open a [discussion][5] and let us know.

Maintainers, when creating a new release, follow the procedure below:

1. Determine an appropriate new version number in the format _a.b.c_, using the following guidelines:
	- The major version (a) should not change.
	- The minor version (b) should be incremented if a new feature has been added or if a bug fix will have a significant user-impact. Reset the patch version to zero if the minor version is incremented.
	- The patch version (c) should be incremented when low-impact bugs are fixed, or security vulnerabilities are patched.
2. Ensure the following are updated _before_ publishing/tagging the new release:
	- [setup.py](setup.py): Match the version to the new release version
	- [Chart.yaml](chart/elastalert2/Chart.yaml): Match chart version and the app version to the new release version (typically keep them in sync)
	- [values.yaml](chart/elastalert2/values.yaml): Match the default image version to the new release version.
	- [Chart README.md](chart/elastalert2/README.md): Match the default image version to the new release version.
	- [Docs](docs/source/running_elastalert.rst): Match the default image version to the new release version.
	- [CHANGELOG.md](CHANGELOG.md): This must contain all PRs and any other relevent notes about this release
3. Publish a [new][1] release.
	- The title (and tag) of the release will be the same value as the new version determined in step 1.
	- Paste the new version change notes from CHANGELOG.md into the description field.
	- Check the box to 'Create a discussion for this release'.
4. Verify that artifacts have been published:
 	- Python PIP package was [published][3] successfully.
 	- Helm chart has been [published][4] successfully.
 	- Container image was [published][2] successfully.

[1]: https://github.com/jertel/elastalert2/releases/new
[2]: https://github.com/jertel/elastalert2/actions/workflows/publish_image.yml
[3]: https://github.com/jertel/elastalert2/actions/workflows/python-publish.yml
[4]: https://github.com/jertel/elastalert2/actions/workflows/upload_chart.yml
[5]: https://github.com/jertel/elastalert2/discussions
