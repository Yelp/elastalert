# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.2.4',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:main',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main',
                            'elastalert=elastalert.elastalert:main']},
    packages=find_packages(),
    package_data={'elastalert': ['schema.yaml', 'es_mappings/**/*.json']},
    install_requires=[
        'apscheduler>=3.3.0,<4.0',
        'aws-requests-auth>=0.4.3',
        'sortedcontainers>=2.4.0',
        'boto3>=1.19.7',
        'croniter>=1.0.15',
        'elasticsearch==7.0.0',
        'envparse>=0.2.0',
        'exotel>=0.1.5',
        'jira>=3.0.1',
        'jsonschema>=4.1.2',
        'prison>=0.2.1',
        'PyStaticConfiguration>=0.10.5',
        'python-dateutil>=2.8.2',
        'PyYAML>=6.0',
        'py-zabbix==1.1.7',
        'requests>=2.26.0',
        'stomp.py>=7.0.0',
        'texttable>=1.6.4',
        'twilio>=6.0.0,<6.58',
        'cffi>=1.11.5',
        'tzlocal==2.1'
    ]
)
