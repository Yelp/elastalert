# Releases

As Elastalert 2 is a community-maintained project, releases will typically contain unrelated contributions without a common theme. It's up to the maintainers to determine when the project is ready for a release, however, if you are looking to use a newly merged feature that hasn't yet been released, feel free to open a [discussion][5] and let us know.

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
4. Create a [new][1] release.
	- The title (and tag) of the release will be the same value as the new version determined in step 1.
	- The description of the release will contain a bulleted list of all merged pull requests, in the following format:
		`- change description #PR - @committer`
		Ex:
		`- Added new Foobar alerts #12345 - @jertel`
	- Check the box to 'Create a discussion for this release'.
	- Save the draft.
5. Verify that artifacts have been published:
 	- Python PIP package was [published][3] successfully.
 	- Helm chart has been [published][4] successfully.
 	- Docker Hub image was [tagged][2] successfully.
6. Wait a minimum of a few hours for community feedback in case someone notices a problem with the the upcoming release.
7. Publish the release.

[1]: https://github.com/jertel/elastalert2/releases/new
[2]: https://hub.docker.com/r/jertel/elastalert2/builds
[3]: https://github.com/jertel/elastalert2/actions/workflows/python-publish.yml
[4]: https://github.com/jertel/elastalert2/actions/workflows/upload_chart.yml
[5]: https://github.com/jertel/elastalert2/discussions