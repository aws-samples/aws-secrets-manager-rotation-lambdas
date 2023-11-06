## AWS Secrets Manager Rotation Lambda Functions

Secrets Manager provides rotation function templates for several types of credentials. To use the templates, see https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_available-rotation-templates.html.

* This fork builds and publishes multi-arch container images as configured in `images.json`.
* The repo(s) that the images are published to are specified in the `.push_to_repos` key.
* Each image builds the folder and then pushes to the repo using the specified tag.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.
