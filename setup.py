# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.0.44',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:check_files',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main']},
    packages=find_packages(),
    package_data={'elastalert': ['schema.yaml']},
    install_requires=[
        'elasticsearch',
        'jira==0.32',  # jira.exceptions is missing from later versions
        'argparse',
        'python-dateutil',
        'PyStaticConfiguration',
        'pyyaml',
        'jsonschema',
        'simplejson',
        'functools32',
    ]
)
