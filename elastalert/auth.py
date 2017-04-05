# -*- coding: utf-8 -*-
import boto3
from aws_requests_auth.aws_auth import AWSRequestsAuth


class Auth(object):

    def __call__(self, host, username, password, aws_region, profile_name):
        """ Return the authorization header.

        :param host: Elasticsearch host.
        :param username: Username used for authenticating the requests to Elasticsearch.
        :param password: Password used for authenticating the requests to Elasticsearch.
        :param aws_region: AWS Region to use. Only required when signing requests.
        :param profile_name: AWS profile to use for connecting. Only required when signing requests.
        """
        if username and password:
            return username + ':' + password

        session = boto3.session.Session(profile_name=profile_name, region_name=aws_region)
        credentials = session.get_credentials()

        return AWSRequestsAuth(
            aws_access_key=credentials.access_key,
            aws_secret_access_key=credentials.secret_key,
            aws_token=credentials.token,
            aws_host=host,
            aws_region=session.region_name,
            aws_service='es')
