# -*- coding: utf-8 -*-
from elastalert.auth import Auth, RefeshableAWSRequestsAuth


def test_auth_none():

    auth = Auth()(
        host='localhost:8080',
        username=None,
        password=None,
        aws_region=None,
        profile_name=None
    )

    assert not auth


def test_auth_username_password():

    auth = Auth()(
        host='localhost:8080',
        username='user',
        password='password',
        aws_region=None,
        profile_name=None
    )

    assert auth == 'user:password'


def test_auth_aws_region():

    auth = Auth()(
        host='localhost:8080',
        username=None,
        password=None,
        aws_region='us-east-1',
        profile_name=None
    )

    assert type(auth) == RefeshableAWSRequestsAuth
    assert auth.aws_region == 'us-east-1'
