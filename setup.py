# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup

base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.2.1',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    classifiers=[
        'Programming Language :: Python :: 3.6',
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
        'PyStaticConfiguration>=0.10.3',
        'PyYAML>=5.1',
        'apscheduler>=3.3.0',
        'aws-requests-auth>=0.3.0',
        'blist>=1.3.6',
        'boto3>=1.4.4',
        'cffi>=1.11.5',
        'configparser>=3.5.0',
        'croniter>=0.3.16',
        'elasticsearch>=7.0.0',
        'envparse>=0.2.0',
        'exotel>=0.1.3',
        'jira>=1.0.10,<1.0.15',
        'jsonschema>=2.6.0',
        'mock>=2.0.0',
        'py-zabbix==1.1.3',
        'python-dateutil>=2.6.0,<2.7.0',
        'python-magic>=0.4.15',
        'requests>=2.10.0',
        'stomp.py>=4.1.17',
        'texttable>=0.8.8',
        'thehive4py>=1.4.4',
        'twilio>=6.0.0,<6.1',
    ]
)
