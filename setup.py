# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.1.6',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:main',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main',
                            'elastalert=elastalert.elastalert:main']},
    packages=find_packages(),
    package_data={'elastalert': ['schema.yaml']},
    install_requires=[
        'aws-requests-auth==0.2.5',
        'blist==1.3.6',
        'boto==2.34.0',
        'botocore==1.4.5',
        'configparser>=3.3.0r2',
        'croniter==0.3.8',
        'elasticsearch<3.0.0',  # Elastalert is not yet compatible with ES5
        'jira==0.32',  # jira.exceptions is missing from later versions
        'jsonschema==2.2.0',
        'mock==1.0.0',
        'oauthlib==0.7.2',
        'PyStaticConfiguration==0.9.0',
        'python-dateutil==2.4.0',
        'PyYAML==3.11',
        'requests-oauthlib==0.4.2',
        'requests==2.5.1',
        'simplejson==3.3.0',
        'six==1.9.0',
        'stomp.py==4.1.11',
        'supervisor==3.1.2',
        'texttable==0.8.4',
        'tlslite==0.4.8',
        'twilio==5.6.0',
        'unittest2==0.8.0',
        'urllib3==1.8.2',
        'wsgiref==0.1.2',
    ]
)
