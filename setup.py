# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.1.2',
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
        'argparse',
        'elasticsearch',
        'jira==0.32',  # jira.exceptions is missing from later versions
        'jsonschema',
        'mock',
        'python-dateutil',
        'PyStaticConfiguration',
        'pyyaml',
        'simplejson',
        'boto',
        'botocore',
        'blist',
        'croniter',
        'configparser',
        'aws-requests-auth',
        'texttable'
    ]
)
