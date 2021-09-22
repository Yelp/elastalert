.. _signingrequests:

Signing requests to Amazon OpenSearch Service
================================================

When using Amazon OpenSearch Service, you need to secure your Elasticsearch
from the outside. Currently, there is no way to secure your Elasticsearch using
network firewall rules, so the only way is to signing the requests using the
access key and secret key for a role or user with permissions on the
Elasticsearch service.

You can sign requests to AWS using any of the standard AWS methods of providing
credentials.
- Environment Variables, ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY``
- AWS Config or Credential Files, ``~/.aws/config`` and ``~/.aws/credentials``
- AWS Instance Profiles, uses the EC2 Metadata service

Using an Instance Profile
-------------------------

Typically, you'll deploy ElastAlert 2 on a running EC2 instance on AWS. You can
assign a role  to this instance that gives it permissions to read from and write
to the Elasticsearch service. When using an Instance Profile, you will need to
specify the ``aws_region`` in the configuration file or set the
``AWS_DEFAULT_REGION`` environment variable.

Using AWS profiles
------------------

You can also create a user with permissions on the Elasticsearch service and
tell ElastAlert 2 to authenticate itself using that user. First, create an AWS
profile in the machine where you'd like to run ElastAlert 2 for the user with
permissions.

You can use the environment variables ``AWS_DEFAULT_PROFILE`` and
``AWS_DEFAULT_REGION`` or add two options to the configuration file:
- ``aws_region``: The AWS region where you want to operate.
- ``profile``: The name of the AWS profile to use to sign the requests.
