# -*- coding: utf-8 -*-
import datetime
import hashlib
import logging
import logging.config
import os
import sys

import ruleloaders
from envparse import Env
from staticconf.loader import yaml_loader
from util import dt_to_ts
from util import dt_to_ts_with_format
from util import dt_to_unix
from util import dt_to_unixms
from util import elastalert_logger
from util import EAException

# schema for rule yaml
rule_schema = jsonschema.Draft4Validator(yaml.load(open(os.path.join(os.path.dirname(__file__), 'schema.yaml')), Loader=yaml.FullLoader))

# Required global (config.yaml) configuration options
required_globals = frozenset(['run_every', 'rules_folder', 'es_host', 'es_port', 'writeback_index', 'buffer_time'])

# Settings that can be derived from ENV variables
env_settings = {'ES_USE_SSL': 'use_ssl',
                'ES_PASSWORD': 'es_password',
                'ES_USERNAME': 'es_username',
                'ES_HOST': 'es_host',
                'ES_PORT': 'es_port',
                'ES_URL_PREFIX': 'es_url_prefix'}

env = Env(ES_USE_SSL=bool)

# Used to map the names of rule loaders to their classes
loader_mapping = {
    'file': ruleloaders.FileRulesLoader
}


def get_module(module_name):
    """ Loads a module and returns a specific object.
    module_name should 'module.file.object'.
    Returns object or raises EAException on error. """
    sys.path.append(os.getcwd())
    try:
        module_path, module_class = module_name.rsplit('.', 1)
        base_module = __import__(module_path, globals(), locals(), [module_class])
        module = getattr(base_module, module_class)
    except (ImportError, AttributeError, ValueError) as e:
        raise EAException("Could not import module %s: %s" % (module_name, e)), None, sys.exc_info()[2]
    return module


def load_conf(args):
    """ Creates a conf dictionary for ElastAlerter. Loads the global
        config file and then each rule found in rules_folder.

        :param args: The parsed arguments to ElastAlert
        :return: The global configuration, a dictionary.
        """
    filename = args.config
    conf = yaml_loader(filename)

    # init logging from config and set log levels according to command line options
    configure_logging(args, conf)

    for env_var, conf_var in env_settings.items():
        val = env(env_var, None)
        if val is not None:
            conf[conf_var] = val

    # Make sure we have all required globals
    if required_globals - frozenset(conf.keys()):
        raise EAException('%s must contain %s' % (filename, ', '.join(required_globals - frozenset(conf.keys()))))

    conf.setdefault('writeback_alias', 'elastalert_alerts')
    conf.setdefault('max_query_size', 10000)
    conf.setdefault('scroll_keepalive', '30s')
    conf.setdefault('max_scrolling_count', 0)
    conf.setdefault('disable_rules_on_error', True)
    conf.setdefault('scan_subdirectories', True)
    conf.setdefault('rules_loader', 'file')

    # Convert run_every, buffer_time into a timedelta object
    try:
        conf['run_every'] = datetime.timedelta(**conf['run_every'])
        conf['buffer_time'] = datetime.timedelta(**conf['buffer_time'])
        if 'alert_time_limit' in conf:
            conf['alert_time_limit'] = datetime.timedelta(**conf['alert_time_limit'])
        else:
            conf['alert_time_limit'] = datetime.timedelta(days=2)
        if 'old_query_limit' in conf:
            conf['old_query_limit'] = datetime.timedelta(**conf['old_query_limit'])
        else:
            conf['old_query_limit'] = datetime.timedelta(weeks=1)
    except (KeyError, TypeError) as e:
        raise EAException('Invalid time format used: %s' % e)

    # Initialise the rule loader and load each rule configuration
    rules_loader_class = loader_mapping.get(conf['rules_loader']) or get_module(conf['rules_loader'])
    rules_loader = rules_loader_class(conf)
    conf['rules_loader'] = rules_loader

    return conf
