# -*- coding: utf-8 -*-
import copy
import datetime
import hashlib
import logging
import os

import alerts
import enhancements
import jsonschema
import ruletypes
import yaml
import yaml.scanner
from opsgenie import OpsGenieAlerter
from staticconf.loader import yaml_loader
from util import dt_to_ts
from util import dt_to_ts_with_format
from util import dt_to_unix
from util import dt_to_unixms
from util import EAException
from util import ts_to_dt
from util import ts_to_dt_with_format
from util import unix_to_dt
from util import unixms_to_dt

# schema for rule yaml
rule_schema = jsonschema.Draft4Validator(yaml.load(open(os.path.join(os.path.dirname(__file__), 'schema.yaml'))))

# Required global (config.yaml) and local (rule.yaml)  configuration options
required_globals = frozenset(['run_every', 'rules_folder', 'es_host', 'es_port', 'writeback_index', 'buffer_time'])
required_locals = frozenset(['alert', 'type', 'name', 'index'])

# Used to map the names of rules to their classes
rules_mapping = {
    'frequency': ruletypes.FrequencyRule,
    'any': ruletypes.AnyRule,
    'spike': ruletypes.SpikeRule,
    'blacklist': ruletypes.BlacklistRule,
    'whitelist': ruletypes.WhitelistRule,
    'change': ruletypes.ChangeRule,
    'flatline': ruletypes.FlatlineRule,
    'new_term': ruletypes.NewTermsRule,
    'cardinality': ruletypes.CardinalityRule
}

# Used to map names of alerts to their classes
alerts_mapping = {
    'email': alerts.EmailAlerter,
    'jira': alerts.JiraAlerter,
    'opsgenie': OpsGenieAlerter,
    'debug': alerts.DebugAlerter,
    'command': alerts.CommandAlerter,
    'sns': alerts.SnsAlerter,
    'hipchat': alerts.HipChatAlerter,
    'slack': alerts.SlackAlerter,
    'pagerduty': alerts.PagerDutyAlerter,
    'victorops': alerts.VictorOpsAlerter,
    'telegram': alerts.TelegramAlerter,
    'gitter': alerts.GitterAlerter,
    'servicenow': alerts.ServiceNowAlerter
}
# A partial ordering of alert types. Relative order will be preserved in the resulting alerts list
# For example, jira goes before email so the ticket # will be added to the resulting email.
alerts_order = {
    'jira': 0,
    'email': 1
}


def get_module(module_name):
    """ Loads a module and returns a specific object.
    module_name should 'module.file.object'.
    Returns object or raises EAException on error. """
    try:
        module_path, module_class = module_name.rsplit('.', 1)
        base_module = __import__(module_path, globals(), locals(), [module_class])
        module = getattr(base_module, module_class)
    except (ImportError, AttributeError, ValueError) as e:
        raise EAException("Could not import module %s: %s" % (module_name, e))
    return module


def load_configuration(filename, conf, args=None):
    """ Load a yaml rule file and fill in the relevant fields with objects.

    :param filename: The name of a rule configuration file.
    :param conf: The global configuration dictionary, used for populating defaults.
    :return: The rule configuration, a dictionary.
    """
    try:
        rule = yaml_loader(filename)
    except yaml.scanner.ScannerError as e:
        raise EAException('Could not parse file %s: %s' % (filename, e))

    rule['rule_file'] = filename
    load_options(rule, conf, args)
    load_modules(rule, args)
    return rule


def load_options(rule, conf, args=None):
    """ Converts time objects, sets defaults, and validates some settings.

    :param rule: A dictionary of parsed YAML from a rule config file.
    :param conf: The global configuration dictionary, used for populating defaults.
    """

    try:
        rule_schema.validate(rule)
    except jsonschema.ValidationError as e:
        raise EAException("Invalid Rule: %s\n%s" % (rule.get('name'), e))

    try:
        # Set all time based parameters
        if 'timeframe' in rule:
            rule['timeframe'] = datetime.timedelta(**rule['timeframe'])
        if 'realert' in rule:
            rule['realert'] = datetime.timedelta(**rule['realert'])
        else:
            rule['realert'] = datetime.timedelta(minutes=1)
        if 'aggregation' in rule and not rule['aggregation'].get('schedule'):
            rule['aggregation'] = datetime.timedelta(**rule['aggregation'])
        if 'query_delay' in rule:
            rule['query_delay'] = datetime.timedelta(**rule['query_delay'])
        if 'buffer_time' in rule:
            rule['buffer_time'] = datetime.timedelta(**rule['buffer_time'])
        if 'exponential_realert' in rule:
            rule['exponential_realert'] = datetime.timedelta(**rule['exponential_realert'])
        if 'kibana4_start_timedelta' in rule:
            rule['kibana4_start_timedelta'] = datetime.timedelta(**rule['kibana4_start_timedelta'])
        if 'kibana4_end_timedelta' in rule:
            rule['kibana4_end_timedelta'] = datetime.timedelta(**rule['kibana4_end_timedelta'])
    except (KeyError, TypeError) as e:
        raise EAException('Invalid time format used: %s' % (e))

    # Set defaults
    rule.setdefault('realert', datetime.timedelta(seconds=0))
    rule.setdefault('aggregation', datetime.timedelta(seconds=0))
    rule.setdefault('query_delay', datetime.timedelta(seconds=0))
    rule.setdefault('timestamp_field', '@timestamp')
    rule.setdefault('filter', [])
    rule.setdefault('timestamp_type', 'iso')
    rule.setdefault('timestamp_format', '%Y-%m-%dT%H:%M:%SZ')
    rule.setdefault('_source_enabled', True)
    rule.setdefault('use_local_time', True)
    rule.setdefault('es_port', conf.get('es_port'))
    rule.setdefault('es_host', conf.get('es_host'))
    rule.setdefault('es_username', conf.get('es_username'))
    rule.setdefault('es_password', conf.get('es_password'))
    rule.setdefault('max_query_size', conf.get('max_query_size'))
    rule.setdefault('scroll_keepalive', conf.get('scroll_keepalive'))
    rule.setdefault('es_conn_timeout', conf.get('es_conn_timeout'))
    rule.setdefault('description', "")

    # Set Elasticsearch options from global config
    if 'es_url_prefix' in conf:
        rule.setdefault('es_url_prefix', conf.get('es_url_prefix'))
    if 'use_ssl' in conf:
        rule.setdefault('use_ssl', conf.get('use_ssl'))

    # Set timestamp_type conversion function, used when generating queries and processing hits
    rule['timestamp_type'] = rule['timestamp_type'].strip().lower()
    if rule['timestamp_type'] == 'iso':
        rule['ts_to_dt'] = ts_to_dt
        rule['dt_to_ts'] = dt_to_ts
    elif rule['timestamp_type'] == 'unix':
        rule['ts_to_dt'] = unix_to_dt
        rule['dt_to_ts'] = dt_to_unix
    elif rule['timestamp_type'] == 'unix_ms':
        rule['ts_to_dt'] = unixms_to_dt
        rule['dt_to_ts'] = dt_to_unixms
    elif rule['timestamp_type'] == 'custom':
        def _ts_to_dt_with_format(ts):
            return ts_to_dt_with_format(ts, ts_format=rule['timestamp_format'])

        def _dt_to_ts_with_format(dt):
            return dt_to_ts_with_format(dt, ts_format=rule['timestamp_format'])

        rule['ts_to_dt'] = _ts_to_dt_with_format
        rule['dt_to_ts'] = _dt_to_ts_with_format
    else:
        raise EAException('timestamp_type must be one of iso, unix, or unix_ms')

    # Set email options from global config
    rule.setdefault('smtp_host', conf.get('smtp_host', 'localhost'))
    rule.setdefault('from_addr', conf.get('from_addr', 'ElastAlert'))
    if 'smtp_port' in conf:
        rule.setdefault('smtp_port', conf.get('smtp_port'))
    if 'smtp_ssl' in conf:
        rule.setdefault('smtp_ssl', conf.get('smtp_ssl'))
    if 'smtp_auth_file' in conf:
        rule.setdefault('smtp_auth_file', conf.get('smtp_auth_file'))
    if 'email_reply_to' in conf:
        rule.setdefault('email_reply_to', conf['email_reply_to'])

    # Set HipChat options from global config
    rule.setdefault('hipchat_msg_color', conf.get('hipchat_msg_color', 'red'))
    rule.setdefault('hipchat_domain', conf.get('hipchat_domain', 'api.hipchat.com'))
    rule.setdefault('hipchat_notify', conf.get('hipchat_notify', True))
    rule.setdefault('hipchat_from', conf.get('hipchat_from', ''))
    rule.setdefault('hipchat_ignore_ssl_errors', conf.get('hipchat_ignore_ssl_errors', False))
    if 'hipchat_auth_token' in conf:
        rule.setdefault('hipchat_auth_token', conf.get('hipchat_auth_token'))
    if 'hipchat_room_id' in conf:
        rule.setdefault('hipchat_room_id', conf.get('hipchat_room_id'))

    # Set slack options from global config
    rule.setdefault('slack_webhook_url', conf.get('slack_webhook_url'))

    # Set pagerduty options from global config
    if 'pagerduty_service_key' in conf:
        rule.setdefault('pagerduty_service_key', conf.get('pagerduty_service_key'))
    if 'pagerduty_client_name' in conf:
        rule.setdefault('pagerduty_client_name', conf.get('pagerduty_client_name'))

    # Make sure we have required options
    if required_locals - frozenset(rule.keys()):
        raise EAException('Missing required option(s): %s' % (', '.join(required_locals - frozenset(rule.keys()))))

    if 'include' in rule and type(rule['include']) != list:
        raise EAException('include option must be a list')

    if isinstance(rule.get('query_key'), list):
        rule['compound_query_key'] = rule['query_key']
        rule['query_key'] = ','.join(rule['query_key'])

    if isinstance(rule.get('aggregate_key'), list):
        rule['compound_aggregate_key'] = rule['aggregate_key']
        rule['aggregate_key'] = ','.join(rule['aggregate_key'])

    # Add QK, CK and timestamp to include
    include = rule.get('include', ['*'])
    if 'query_key' in rule:
        include.append(rule['query_key'])
    if 'compound_query_key' in rule:
        include += rule['compound_query_key']
    if 'compound_aggregate_key' in rule:
        include += rule['compound_aggregate_key']
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

    # Get Kibana link options from global config
    if 'generate_kibana_link' in conf:
        rule.setdefault('generate_kibana_link', conf.get('generate_kibana_link'))
    if 'kibana_url' in conf:
        rule.setdefault('kibana_url', conf.get('kibana_url'))

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


def load_modules(rule, args=None):
    """ Loads things that could be modules. Enhancements, alerts and rule type. """
    # Set match enhancements
    match_enhancements = []
    for enhancement_name in rule.get('match_enhancements', []):
        if enhancement_name in dir(enhancements):
            enhancement = getattr(enhancements, enhancement_name)
        else:
            enhancement = get_module(enhancement_name)
        if not issubclass(enhancement, enhancements.BaseEnhancement):
            raise EAException("Enhancement module %s not a subclass of BaseEnhancement" % (enhancement_name))
        match_enhancements.append(enhancement(rule))
    rule['match_enhancements'] = match_enhancements

    # Convert rule type into RuleType object
    if rule['type'] in rules_mapping:
        rule['type'] = rules_mapping[rule['type']]
    else:
        rule['type'] = get_module(rule['type'])
        if not issubclass(rule['type'], ruletypes.RuleType):
            raise EAException('Rule module %s is not a subclass of RuleType' % (rule['type']))

    # Make sure we have required alert and type options
    reqs = rule['type'].required_options

    if reqs - frozenset(rule.keys()):
        raise EAException('Missing required option(s): %s' % (', '.join(reqs - frozenset(rule.keys()))))
    # Instantiate rule
    try:
        rule['type'] = rule['type'](rule, args)
    except (KeyError, EAException) as e:
        raise EAException('Error initializing rule %s: %s' % (rule['name'], e))
    # Instantiate alert
    rule['alert'] = load_alerts(rule, alert_field=rule['alert'])


def get_file_paths(conf, use_rule=None):
    # Passing a filename directly can bypass rules_folder and .yaml checks
    if use_rule and os.path.isfile(use_rule):
        return [use_rule]
    rule_folder = conf['rules_folder']
    rule_files = []
    if conf['scan_subdirectories']:
        for root, folders, files in os.walk(rule_folder):
            for filename in files:
                if use_rule and use_rule != filename:
                    continue
                if filename.endswith('.yaml'):
                    rule_files.append(os.path.join(root, filename))
    else:
        for filename in os.listdir(rule_folder):
            fullpath = os.path.join(rule_folder, filename)
            if os.path.isfile(fullpath) and filename.endswith('.yaml'):
                rule_files.append(fullpath)
    return rule_files


def load_alerts(rule, alert_field):
    def normalize_config(alert):
        """Alert config entries are either "alertType" or {"alertType": {"key": "data"}}.
        This function normalizes them both to the latter format. """
        if isinstance(alert, basestring):
            return alert, rule
        elif isinstance(alert, dict):
            name, config = iter(alert.items()).next()
            config_copy = copy.copy(rule)
            config_copy.update(config)  # warning, this (intentionally) mutates the rule dict
            return name, config_copy
        else:
            raise EAException()

    def create_alert(alert, alert_config):
        alert_class = alerts_mapping.get(alert) or get_module(alert)
        if not issubclass(alert_class, alerts.Alerter):
            raise EAException('Alert module %s is not a subclass of Alerter' % (alert))
        missing_options = (rule['type'].required_options | alert_class.required_options) - frozenset(alert_config or [])
        if missing_options:
            raise EAException('Missing required option(s): %s' % (', '.join(missing_options)))
        return alert_class(alert_config)

    try:
        if type(alert_field) != list:
            alert_field = [alert_field]

        alert_field = [normalize_config(x) for x in alert_field]
        alert_field = sorted(alert_field, key=lambda (a, b): alerts_order.get(a, -1))
        # Convert all alerts into Alerter objects
        alert_field = [create_alert(a, b) for a, b in alert_field]

    except (KeyError, EAException) as e:
        raise EAException('Error initiating alert %s: %s' % (rule['alert'], e))

    return alert_field


def load_rules(args):
    """ Creates a conf dictionary for ElastAlerter. Loads the global
    config file and then each rule found in rules_folder.

    :param args: The parsed arguments to ElastAlert
    :return: The global configuration, a dictionary.
    """
    names = []
    filename = args.config
    conf = yaml_loader(filename)
    use_rule = args.rule

    # Make sure we have all required globals
    if required_globals - frozenset(conf.keys()):
        raise EAException('%s must contain %s' % (filename, ', '.join(required_globals - frozenset(conf.keys()))))

    conf.setdefault('max_query_size', 10000)
    conf.setdefault('scroll_keepalive', '30s')
    conf.setdefault('disable_rules_on_error', True)
    conf.setdefault('scan_subdirectories', True)

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
    rules = []
    rule_files = get_file_paths(conf, use_rule)
    for rule_file in rule_files:
        try:
            rule = load_configuration(rule_file, conf, args)
            if rule['name'] in names:
                raise EAException('Duplicate rule named %s' % (rule['name']))
        except EAException as e:
            raise EAException('Error loading file %s: %s' % (rule_file, e))

        rules.append(rule)
        names.append(rule['name'])

    conf['rules'] = rules
    return conf


def get_rule_hashes(conf, use_rule=None):
    rule_files = get_file_paths(conf, use_rule)
    rule_mod_times = {}
    for rule_file in rule_files:
        with open(rule_file) as fh:
            rule_mod_times[rule_file] = hashlib.sha1(fh.read()).digest()
    return rule_mod_times
