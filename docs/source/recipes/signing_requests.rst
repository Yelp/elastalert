.. _signingrequests:

Signing requests to Amazon ElasticSearch service
============

When using Amazon ElasticSearch service, you need to secure your ElasticSearch from the outside.
Currently, there is no way to secure your ElasticSearch using network firewall rules, so the only way is to signing the requests using the access key and secret key for a role or user with permissions on the ElasticSearch service.

We offer two different options to sign ElastAlert requests to ElasticSearch: using instance roles and boto profiles.

Using instance role
-------------------
Typically, you'll deploy ElastAlert on a running EC2 instance on AWS. You can assign a role to this instance that gives it permissions to read from and write to the ElasticSearch service.
Then you just need to add the ``aws_region`` option to the configuration file. This will tell ElastAlert to sign the requests to ElasticSearch.

Using boto profiles
--------------------
You can also create a user with permissions on the ElasticSearch service and tell ElastAlert to authenticate itself using that user.
First, create a boto profile in the machine where you'd like to run ElastAlert for the user with permissions. Then, just add two options to the configuration file:
- ``aws_region``: that tells ElastAlert to sign the requests to ElasticSearch. It's the AWS region where you want to operate.
- ``boto_profile``: with the name of the boto profile to use to sign the requests.

