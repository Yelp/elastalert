import datetime

import loaders
from envparse import Env
from staticconf.loader import yaml_loader
from util import EAException
from util import get_module


# Required global (config.yaml) configuration options
required_globals = frozenset(['run_every', 'es_host', 'es_port', 'writeback_index', 'buffer_time'])

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
    conf = yaml_loader(filename)

    for env_var, conf_var in env_settings.items():
        val = env(env_var, None)
        if val is not None:
            conf[conf_var] = val

    for key, value in (defaults.iteritems() if defaults is not None else []):
        if key not in conf:
            conf[key] = value

    for key, value in (overwrites.iteritems() if overwrites is not None else []):
        conf[key] = value

    # Make sure we have all required globals
    if required_globals - frozenset(conf.keys()):
        raise EAException('%s must contain %s' % (filename, ', '.join(required_globals - frozenset(conf.keys()))))

    conf.setdefault('max_query_size', 10000)
    conf.setdefault('scroll_keepalive', '30s')
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
    # Make sure we have all the required globals for the loader
    # Make sure we have all required globals
    if rules_loader.required_globals - frozenset(conf.keys()):
        raise EAException(
            '%s must contain %s' % (filename, ', '.join(rules_loader.required_globals - frozenset(conf.keys()))))

    return conf
