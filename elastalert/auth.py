# -*- coding: utf-8 -*-
import os
import configparser

from aws_requests_auth.aws_auth import AWSRequestsAuth

from botocore.credentials import InstanceMetadataProvider, InstanceMetadataFetcher


class Auth(object):

    def __call__(self, host, username, password, aws_region, boto_profile):
        """ Return the authorization header. If 'boto_profile' is passed, it'll be used. Otherwise it'll sign requests
        with instance role.

        :param host: Elasticsearch host.
        :param username: Username used for authenticating the requests to Elasticsearch.
        :param password: Password used for authenticating the requests to Elasticsearch.
        :param aws_region: AWS Region to use. Only required when signing requests.
        :param boto_profile: Boto profile to use for connecting. Only required when signing requests.
        """
        if username and password:
            return username + ':' + password

        if not aws_region:
            return None

        if boto_profile:
            # Executing ElastAlert from machine with aws credentials
            config = configparser.ConfigParser()
            config.read(os.path.expanduser('~') + '/.aws/credentials')
            aws_access_key_id = str(config[boto_profile]['aws_access_key_id'])
            aws_secret_access_key = str(config[boto_profile]['aws_secret_access_key'])
            aws_token = None
        else:
            # Executing ElastAlert from machine deployed with specific role
            provider = InstanceMetadataProvider(
                iam_role_fetcher=InstanceMetadataFetcher(timeout=1000, num_attempts=2))
            aws_credentials = provider.load()
            aws_access_key_id = str(aws_credentials.access_key)
            aws_secret_access_key = str(aws_credentials.secret_key)
            aws_token = str(aws_credentials.token)

        return AWSRequestsAuth(aws_access_key=aws_access_key_id,
                               aws_secret_access_key=aws_secret_access_key,
                               aws_token=aws_token,
                               aws_host=host,
                               aws_region=aws_region,
                               aws_service='es')
