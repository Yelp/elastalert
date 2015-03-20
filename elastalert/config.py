# -*- coding: utf-8 -*-
import datetime
import hashlib
import logging
import os

import alerts
import enhancements
import ruletypes
import yaml
import yaml.scanner
from staticconf.loader import yaml_loader
from util import EAException


# Required global (config.yaml) and local (rule.yaml)  configuration options
required_globals = frozenset(['run_every', 'rules_folder', 'es_host', 'es_port', 'writeback_index', 'buffer_time'])
required_locals = frozenset(['alert', 'type', 'name', 'es_host', 'es_port', 'index'])

# Used to map the names of rules to their classes
rules_mapping = {
    'frequency': ruletypes.FrequencyRule,
    'any': ruletypes.AnyRule,
    'spike': ruletypes.SpikeRule,
    'blacklist': ruletypes.BlacklistRule,
    'whitelist': ruletypes.WhitelistRule,
    'change': ruletypes.ChangeRule,
    'flatline': ruletypes.FlatlineRule
}

# Used to map names of alerts to their classes
alerts_mapping = {
    'email': alerts.EmailAlerter,
    'jira': alerts.JiraAlerter,
    'debug': alerts.DebugAlerter
}


def get_module(module_name):
    """ Loads a module and returns a specific object.
    module_name should 'module.file.object'.
    Returns object or raises EAException on error. """
    try:
        module_path, module_class = module_name.rsplit('.', 1)
        base_module = __import__(module_path, globals(), locals(), [module_class])
        module = getattr(base_module, module_class)
    except (ImportError, AttributeError, ValueError):
        raise EAException("Could not import match module %s" % (module_name))
    return module


def load_configuration(filename, testing=False):
    """ Load a yaml rule file and fill in the relevant fields with objects.

    :param filename: The name of a rule configuration file.
    :return: The rule configuration, a dictionary.
    """
    try:
        rule = yaml_loader(filename)
    except yaml.scanner.ScannerError as e:
        raise EAException('Could not parse file %s: %s' % (filename, e))

    rule['rule_file'] = os.path.split(filename)[-1]

    try:
        # Set all time based parameters
        if 'timeframe' in rule:
            rule['timeframe'] = datetime.timedelta(**rule['timeframe'])
        if 'realert' in rule:
            rule['realert'] = datetime.timedelta(**rule['realert'])
        else:
            rule['realert'] = datetime.timedelta(minutes=1)
        if 'aggregation' in rule:
            rule['aggregation'] = datetime.timedelta(**rule['aggregation'])
        if 'query_delay' in rule:
            rule['query_delay'] = datetime.timedelta(**rule['query_delay'])
        if 'buffer_time' in rule:
            rule['buffer_time'] = datetime.timedelta(**rule['buffer_time'])
    except (KeyError, TypeError) as e:
        raise EAException('Invalid time format used: %s' % (e))

    # Set defaults
    rule.setdefault('realert', datetime.timedelta(seconds=0))
    rule.setdefault('aggregation', datetime.timedelta(seconds=0))
    rule.setdefault('query_delay', datetime.timedelta(seconds=0))
    rule.setdefault('timestamp_field', '@timestamp')
    rule.setdefault('filter', [])
    rule.setdefault('use_local_time', True)

    # Make sure we have required options
    if required_locals - frozenset(rule.keys()):
        raise EAException('Missing required option(s): %s' % (', '.join(required_locals - frozenset(rule.keys()))))

    if 'include' in rule and type(rule['include']) != list:
        raise EAException('include option must be a list')

    # Add QK, CK and timestamp to include
    include = rule.get('include', [])
    if 'query_key' in rule:
        include.append(rule['query_key'])
    if 'compare_key' in rule:
        include.append(rule['compare_key'])
    if 'top_count_keys' in rule:
        include += rule['top_count_keys']
    include.append(rule['timestamp_field'])
    rule['include'] = list(set(include))

    # Change top_count_keys to .raw
    if 'top_count_keys' in rule and rule.get('raw_count_keys', True):
        keys = rule.get('top_count_keys')
        rule['top_count_keys'] = [key + '.raw' if not key.endswith('.raw') else key for key in keys]

    # Check that generate_kibana_url is compatible with the filters
    if rule.get('generate_kibana_link'):
        for es_filter in rule.get('filter'):
            if es_filter:
                if 'not' in es_filter:
                    es_filter = es_filter['not']
                if 'query' in es_filter:
                    es_filter = es_filter['query']
                if es_filter.keys()[0] not in ('term', 'query_string', 'range'):
                    raise EAException('generate_kibana_link is incompatible with filters other than term, query_string and range. '
                                      'Consider creating a dashboard and using use_kibana_dashboard instead.')

    # Check that doc_type is provided if use_count/terms_query
    if rule.get('use_count_query') or rule.get('use_terms_query'):
        if 'doc_type' not in rule:
            raise EAException('doc_type must be specified.')

    # Check that query_key is set if use_terms_query
    if rule.get('use_terms_query'):
        if 'query_key' not in rule:
            raise EAException('query_key must be specified with use_terms_query')

    # Warn if use_strf_index is used with %y, %M or %D
    # (%y = short year, %M = minutes, %D = full date)
    if rule.get('use_strftime_index'):
        for token in ['%y', '%M', '%D']:
            if token in rule.get('index'):
                logging.warning('Did you mean to use %s in the index? '
                                'The index will be formatted like %s' % (token,
                                                                         datetime.datetime.now().strftime(rule.get('index'))))

    if testing:
        return rule

    # Set match enhancements
    match_enhancements = []
    if not testing:
        for enhancement_name in rule.get('match_enhancements', []):
            if enhancement_name in dir(enhancements):
                enhancement = getattr(enhancements, enhancement_name)
            else:
                enhancement = get_module(enhancement_name)
            if not issubclass(enhancement, enhancements.BaseEnhancement):
                raise EAException("Enhancement module %s not a subclass of BaseEnhancement" % (enhancement_name))
            match_enhancements.append(enhancement(rule))
    rule['match_enhancements'] = match_enhancements

    # Convert all alerts into Alerter objects
    rule_alerts = []
    if type(rule['alert']) != list:
        rule['alert'] = [rule['alert']]
    for alert in rule['alert']:
        if alert in alerts_mapping:
            rule_alerts.append(alerts_mapping[alert])
        else:
            rule_alerts.append(get_module(alert))
            if not issubclass(rule_alerts[-1], alerts.Alerter):
                raise EAException('Alert module %s is not a subclass of Alerter' % (alert))
        rule['alert'] = rule_alerts

    # Convert rule type into RuleType object
    if rule['type'] in rules_mapping:
        rule['type'] = rules_mapping[rule['type']]
    else:
        rule['type'] = get_module(rule['type'])
        if not issubclass(rule['type'], ruletypes.RuleType):
            raise EAException('Rule module %s is not a subclass of RuleType' % (rule['type']))

    # Make sure we have required alert and type options
    reqs = rule['type'].required_options
    for alert in rule['alert']:
        reqs = reqs.union(alert.required_options)
    if reqs - frozenset(rule.keys()):
        raise EAException('Missing required option(s): %s' % (', '.join(reqs - frozenset(rule.keys()))))

    # Instantiate alert
    try:
        rule['alert'] = [alert(rule) for alert in rule['alert']]
    except (KeyError, EAException) as e:
        raise EAException('Error initiating alert %s: %s' % (rule['alert'], e))

    # Instantiate rule
    try:
        rule['type'] = rule['type'](rule)
    except (KeyError, EAException) as e:
        raise EAException('Error initializing rule %s: %s' % (rule['name'], e))

    return rule


def load_rules(filename, use_rule=None):
    """ Creates a conf dictionary for ElastAlerter. Loads the global
    config file and then each rule found in rules_folder.

    :param filename: Name of the global configuration file.
    :param use_rule: Only load the rule which has this filename.
    :return: The global configuration, a dictionary.
    """
    names = []
    conf = yaml_loader(filename)

    # Make sure we have all required globals
    if required_globals - frozenset(conf.keys()):
        raise EAException('%s must contain %s' % (filename, ', '.join(required_globals - frozenset(conf.keys()))))

    conf.setdefault('max_query_size', 100000)

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
        raise EAException('Invalid time format used: %s' % (e))

    # Load each rule configuration file
    rule_folder = conf['rules_folder']
    rule_files = os.listdir(rule_folder)
    rules = []
    for rule_file in rule_files:
        if use_rule and rule_file != use_rule:
            continue
        if '.yaml' == rule_file[-5:]:
            try:
                rule = load_configuration(os.path.join(rule_folder, rule_file))
                if rule['name'] in names:
                    raise EAException('Duplicate rule named %s' % (rule['name']))
            except EAException as e:
                raise EAException('Error loading file %s: %s' % (rule_file, e))

            rules.append(rule)
            names.append(rule['name'])

    if not rules:
        logging.exception('No rules loaded. Exiting')
        exit(1)

    conf['rules'] = rules
    return conf


def get_rule_hashes(conf):
    rules_folder = conf['rules_folder']
    rule_files = os.listdir(rules_folder)
    rule_mod_times = {}
    for rule_file in rule_files:
        if '.yaml' != rule_file[-5:]:
            continue
        with open(os.path.join(rules_folder, rule_file)) as fh:
            rule_mod_times[rule_file] = hashlib.sha1(fh.read()).digest()
    return rule_mod_times
