# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert2',
    version='2.2.0',
    description='Automated rule-based alerting for Elasticsearch',
    setup_requires='setuptools',
    license='Apache 2.0',
    classifiers=[
        'Programming Language :: Python :: 3.9',
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
        'aws-requests-auth>=0.3.0',
        'sortedcontainers>=2.2.2',
        'boto3>=1.4.4',
        'croniter>=0.3.16',
        'elasticsearch==7.0.0',
        'envparse>=0.2.0',
        'exotel>=0.1.3',
        'jira>=2.0.0',
        'Jinja2==3.0.1',
        'jsonschema>=3.0.2',
        'prison>=0.1.2',
        'prometheus_client>=0.10.1',
        'py-zabbix>=1.1.3',
        'python-dateutil>=2.6.0,<2.9.0',
        'PyYAML>=5.1',
        'requests>=2.10.0',
        'stomp.py>=4.1.17',
        'texttable>=0.8.8',
        'twilio>=6.0.0,<6.58',
        'cffi>=1.11.5',
        'statsd-tags==3.2.1.post1',
        'tzlocal<3.0'
    ]
)
