# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


# Hard linking doesn't work inside VirtualBox/VMWare shared folders. This means
# that you can't use tox in a directory that is being shared with Vagrant,
# since tox relies on `python setup.py sdist` which uses hard links. As a
# workaround, disable hard-linking if setup.py is a descendant of /vagrant.
# See
# https://stackoverflow.com/questions/7719380/python-setup-py-sdist-error-operation-not-permitted
# for more details.
if os.path.abspath(__file__).split(os.path.sep)[1] == 'vagrant':
    del os.link

base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.0.53',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:main',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main']},
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
    ]
)
