# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.1.15',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:main',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main',
                            'elastalert=elastalert.elastalert:main']},
    packages=find_packages(),
    package_data={'elastalert': ['schema.yaml']},
    install_requires=[
        'aws-requests-auth>=0.3.0',
        'blist>=1.3.6',
        'boto3>=1.4.4',
        'configparser>=3.5.0',
        'croniter>=0.3.16',
        'elasticsearch',
        'exotel>=0.1.3',
        'jira>=1.0.10',
        'jsonschema>=2.6.0',
        'mock>=2.0.0',
        'PyStaticConfiguration>=0.10.3',
        'python-dateutil>=2.6.0',
        'PyYAML>=3.12',
        'requests>=2.10.0',
        'simplejson>=3.10.0',
        'stomp.py>=4.1.17',
        'texttable>=0.8.8',
        'twilio>=6.0.0,<6.1',
    ]
)
