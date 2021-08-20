# -*- coding: utf-8 -*-
import datetime
import logging
import logging.config

from envparse import Env

from elastalert import loaders
from elastalert.util import EAException
from elastalert.util import elastalert_logger
from elastalert.util import get_module
from elastalert.yaml import read_yaml

# Required global (config.yaml) configuration options
required_globals = frozenset(['run_every', 'es_host', 'es_port', 'writeback_index', 'buffer_time'])

# Settings that can be derived from ENV variables
env_settings = {'ES_USE_SSL': 'use_ssl',
                'ES_BEARER': 'es_bearer',
                'ES_PASSWORD': 'es_password',
                'ES_USERNAME': 'es_username',
                'ES_API_KEY': 'es_api_key',
                'ES_HOST': 'es_host',
                'ES_PORT': 'es_port',
                'ES_URL_PREFIX': 'es_url_prefix',
                'STATSD_INSTANCE_TAG': 'statsd_instance_tag',
                'STATSD_HOST': 'statsd_host'}

env = Env(ES_USE_SSL=bool)


# Used to map the names of rule loaders to their classes
loader_mapping = {
    'file': loaders.FileRulesLoader,
}


def load_conf(args, defaults=None, overwrites=None):
    """ Creates a conf dictionary for ElastAlerter. Loads the global
        config file and then each rule found in rules_folder.

        :param args: The parsed arguments to ElastAlert
        :param defaults: Dictionary of default conf values
        :param overwrites: Dictionary of conf values to override
        :return: The global configuration, a dictionary.
        """
    filename = args.config
    if filename:
        conf = read_yaml(filename)
    else:
        try:
            conf = read_yaml('config.yaml')
        except FileNotFoundError:
            raise EAException('No --config or config.yaml found')

    # init logging from config and set log levels according to command line options
    configure_logging(args, conf)

    for env_var, conf_var in list(env_settings.items()):
        val = env(env_var, None)
        if val is not None:
            conf[conf_var] = val

    for key, value in (iter(defaults.items()) if defaults is not None else []):
        if key not in conf:
            conf[key] = value

    for key, value in (iter(overwrites.items()) if overwrites is not None else []):
        conf[key] = value

    # Make sure we have all required globals
    if required_globals - frozenset(list(conf.keys())):
        raise EAException('%s must contain %s' % (filename, ', '.join(required_globals - frozenset(list(conf.keys())))))

    conf.setdefault('max_query_size', 10000)
    conf.setdefault('scroll_keepalive', '30s')
    conf.setdefault('max_scrolling_count', 0)
    conf.setdefault('disable_rules_on_error', True)
    conf.setdefault('scan_subdirectories', True)
    conf.setdefault('rules_loader', 'file')
    conf.setdefault('custum_pretty_ts_format', None)

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
    # Make sure we have all the required globals for the loader
    # Make sure we have all required globals
    if rules_loader.required_globals - frozenset(list(conf.keys())):
        raise EAException(
            '%s must contain %s' % (filename, ', '.join(rules_loader.required_globals - frozenset(list(conf.keys())))))

    return conf


def configure_logging(args, conf):
    # configure logging from config file if provided
    if 'logging' in conf:
        # load new logging config
        logging.config.dictConfig(conf['logging'])

    if args.verbose and args.debug:
        elastalert_logger.info(
            "Note: --debug and --verbose flags are set. --debug takes precedent."
        )

    # re-enable INFO log level on elastalert_logger in verbose/debug mode
    # (but don't touch it if it is already set to INFO or below by config)
    if args.verbose or args.debug:
        if elastalert_logger.level > logging.INFO or elastalert_logger.level == logging.NOTSET:
            elastalert_logger.setLevel(logging.INFO)

    if args.debug:
        elastalert_logger.info(
            """Note: In debug mode, alerts will be logged to console but NOT actually sent.
            To send them but remain verbose, use --verbose instead."""
        )

    if not args.es_debug and 'logging' not in conf:
        logging.getLogger('elasticsearch').setLevel(logging.WARNING)

    if args.es_debug_trace:
        tracer = logging.getLogger('elasticsearch.trace')
        tracer.setLevel(logging.INFO)
        tracer.addHandler(logging.FileHandler(args.es_debug_trace))
