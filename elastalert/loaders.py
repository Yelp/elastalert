# -*- coding: utf-8 -*-
import copy
import datetime
import hashlib
import logging
import os
import sys

import jsonschema
import yaml
import yaml.scanner
from staticconf.loader import yaml_loader

from . import alerts
from . import enhancements
from . import ruletypes
from .opsgenie import OpsGenieAlerter
from .util import dt_to_ts
from .util import dt_to_ts_with_format
from .util import dt_to_unix
from .util import dt_to_unixms
from .util import EAException
from .util import get_module
from .util import ts_to_dt
from .util import ts_to_dt_with_format
from .util import unix_to_dt
from .util import unixms_to_dt


class RulesLoader(object):
    # import rule dependency
    import_rules = {}

    # Required global (config.yaml) configuration options for the loader
    required_globals = frozenset([])

    # Required local (rule.yaml) configuration options
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
        'cardinality': ruletypes.CardinalityRule,
        'metric_aggregation': ruletypes.MetricAggregationRule,
        'percentage_match': ruletypes.PercentageMatchRule,
        'spike_aggregation': ruletypes.SpikeMetricAggregationRule,
    }

    # Used to map names of alerts to their classes
    alerts_mapping = {
        'email': alerts.EmailAlerter,
        'jira': alerts.JiraAlerter,
        'opsgenie': OpsGenieAlerter,
        'stomp': alerts.StompAlerter,
        'debug': alerts.DebugAlerter,
        'command': alerts.CommandAlerter,
        'sns': alerts.SnsAlerter,
        'hipchat': alerts.HipChatAlerter,
        'stride': alerts.StrideAlerter,
        'ms_teams': alerts.MsTeamsAlerter,
        'slack': alerts.SlackAlerter,
        'mattermost': alerts.MattermostAlerter,
        'pagerduty': alerts.PagerDutyAlerter,
        'exotel': alerts.ExotelAlerter,
        'twilio': alerts.TwilioAlerter,
        'victorops': alerts.VictorOpsAlerter,
        'telegram': alerts.TelegramAlerter,
        'googlechat': alerts.GoogleChatAlerter,
        'gitter': alerts.GitterAlerter,
        'servicenow': alerts.ServiceNowAlerter,
        'alerta': alerts.AlertaAlerter,
        'post': alerts.HTTPPostAlerter,
        'hivealerter': alerts.HiveAlerter
    }

    # A partial ordering of alert types. Relative order will be preserved in the resulting alerts list
    # For example, jira goes before email so the ticket # will be added to the resulting email.
    alerts_order = {
        'jira': 0,
        'email': 1
    }

    base_config = {}

    def __init__(self, conf):
        # schema for rule yaml
        self.rule_schema = jsonschema.Draft7Validator(
            yaml.load(open(os.path.join(os.path.dirname(__file__), 'schema.yaml')), Loader=yaml.FullLoader))

        self.base_config = copy.deepcopy(conf)

    def load(self, conf, args=None):
        """
        Discover and load all the rules as defined in the conf and args.
        :param dict conf: Configuration dict
        :param dict args: Arguments dict
        :return: List of rules
        :rtype: list
        """
        names = []
        use_rule = None if args is None else args.rule

        # Load each rule configuration file
        rules = []
        rule_files = self.get_names(conf, use_rule)
        for rule_file in rule_files:
            try:
                rule = self.load_configuration(rule_file, conf, args)
                # A rule failed to load, don't try to process it
                if not rule:
                    logging.error('Invalid rule file skipped: %s' % rule_file)
                    continue
                # By setting "is_enabled: False" in rule file, a rule is easily disabled
                if 'is_enabled' in rule and not rule['is_enabled']:
                    continue
                if rule['name'] in names:
                    raise EAException('Duplicate rule named %s' % (rule['name']))
            except EAException as e:
                raise EAException('Error loading file %s: %s' % (rule_file, e))

            rules.append(rule)
            names.append(rule['name'])

        return rules

    def get_names(self, conf, use_rule=None):
        """
        Return a list of rule names that can be passed to `get_yaml` to retrieve.
        :param dict conf: Configuration dict
        :param str use_rule: Limit to only specified rule
        :return: A list of rule names
        :rtype: list
        """
        raise NotImplementedError()

    def get_hashes(self, conf, use_rule=None):
        """
        Discover and get the hashes of all the rules as defined in the conf.
        :param dict conf: Configuration
        :param str use_rule: Limit to only specified rule
        :return: Dict of rule name to hash
        :rtype: dict
        """
        raise NotImplementedError()

    def get_yaml(self, filename):
        """
        Get and parse the yaml of the specified rule.
        :param str filename: Rule to get the yaml
        :return: Rule YAML dict
        :rtype: dict
        """
        raise NotImplementedError()

    def get_import_rule(self, rule):
        """
        Retrieve the name of the rule to import.
        :param dict rule: Rule dict
        :return: rule name that will all `get_yaml` to retrieve the yaml of the rule
        :rtype: str
        """
        return rule['import']

    def load_configuration(self, filename, conf, args=None):
        """ Load a yaml rule file and fill in the relevant fields with objects.

        :param str filename: The name of a rule configuration file.
        :param dict conf: The global configuration dictionary, used for populating defaults.
        :param dict args: Arguments
        :return: The rule configuration, a dictionary.
        """
        rule = self.load_yaml(filename)
        self.load_options(rule, conf, filename, args)
        self.load_modules(rule, args)
        return rule

    def load_yaml(self, filename):
        """
        Load the rule including all dependency rules.
        :param str filename: Rule to load
        :return: Loaded rule dict
        :rtype: dict
        """
        rule = {
            'rule_file': filename,
        }

        self.import_rules.pop(filename, None)  # clear `filename` dependency
        while True:
            loaded = self.get_yaml(filename)

            # Special case for merging filters - if both files specify a filter merge (AND) them
            if 'filter' in rule and 'filter' in loaded:
                rule['filter'] = loaded['filter'] + rule['filter']

            loaded.update(rule)
            rule = loaded
            if 'import' in rule:
                # Find the path of the next file.
                import_filename = self.get_import_rule(rule)
                # set dependencies
                rules = self.import_rules.get(filename, [])
                rules.append(import_filename)
                self.import_rules[filename] = rules
                filename = import_filename
                del (rule['import'])  # or we could go on forever!
            else:
                break

        return rule

    def load_options(self, rule, conf, filename, args=None):
        """ Converts time objects, sets defaults, and validates some settings.

        :param rule: A dictionary of parsed YAML from a rule config file.
        :param conf: The global configuration dictionary, used for populating defaults.
        :param filename: Name of the rule
        :param args: Arguments
        """
        self.adjust_deprecated_values(rule)

        try:
            self.rule_schema.validate(rule)
        except jsonschema.ValidationError as e:
            raise EAException("Invalid Rule file: %s\n%s" % (filename, e))

        try:
            # Set all time based parameters
            if 'timeframe' in rule:
                rule['timeframe'] = datetime.timedelta(**rule['timeframe'])
            if 'realert' in rule:
                rule['realert'] = datetime.timedelta(**rule['realert'])
            else:
                if 'aggregation' in rule:
                    rule['realert'] = datetime.timedelta(minutes=0)
                else:
                    rule['realert'] = datetime.timedelta(minutes=1)
            if 'aggregation' in rule and not rule['aggregation'].get('schedule'):
                rule['aggregation'] = datetime.timedelta(**rule['aggregation'])
            if 'query_delay' in rule:
                rule['query_delay'] = datetime.timedelta(**rule['query_delay'])
            if 'buffer_time' in rule:
                rule['buffer_time'] = datetime.timedelta(**rule['buffer_time'])
            if 'run_every' in rule:
                rule['run_every'] = datetime.timedelta(**rule['run_every'])
            if 'bucket_interval' in rule:
                rule['bucket_interval_timedelta'] = datetime.timedelta(**rule['bucket_interval'])
            if 'exponential_realert' in rule:
                rule['exponential_realert'] = datetime.timedelta(**rule['exponential_realert'])
            if 'kibana4_start_timedelta' in rule:
                rule['kibana4_start_timedelta'] = datetime.timedelta(**rule['kibana4_start_timedelta'])
            if 'kibana4_end_timedelta' in rule:
                rule['kibana4_end_timedelta'] = datetime.timedelta(**rule['kibana4_end_timedelta'])
            if 'kibana_discover_from_timedelta' in rule:
                rule['kibana_discover_from_timedelta'] = datetime.timedelta(**rule['kibana_discover_from_timedelta'])
            if 'kibana_discover_to_timedelta' in rule:
                rule['kibana_discover_to_timedelta'] = datetime.timedelta(**rule['kibana_discover_to_timedelta'])
        except (KeyError, TypeError) as e:
            raise EAException('Invalid time format used: %s' % e)

        # Set defaults, copy defaults from config.yaml
        for key, val in list(self.base_config.items()):
            rule.setdefault(key, val)
        rule.setdefault('name', os.path.splitext(filename)[0])
        rule.setdefault('realert', datetime.timedelta(seconds=0))
        rule.setdefault('aggregation', datetime.timedelta(seconds=0))
        rule.setdefault('query_delay', datetime.timedelta(seconds=0))
        rule.setdefault('timestamp_field', '@timestamp')
        rule.setdefault('filter', [])
        rule.setdefault('timestamp_type', 'iso')
        rule.setdefault('timestamp_format', '%Y-%m-%dT%H:%M:%SZ')
        rule.setdefault('_source_enabled', True)
        rule.setdefault('use_local_time', True)
        rule.setdefault('description', "")

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
                ts = dt_to_ts_with_format(dt, ts_format=rule['timestamp_format'])
                if 'timestamp_format_expr' in rule:
                    # eval expression passing 'ts' and 'dt'
                    return eval(rule['timestamp_format_expr'], {'ts': ts, 'dt': dt})
                else:
                    return ts

            rule['ts_to_dt'] = _ts_to_dt_with_format
            rule['dt_to_ts'] = _dt_to_ts_with_format
        else:
            raise EAException('timestamp_type must be one of iso, unix, or unix_ms')

        # Add support for client ssl certificate auth
        if 'verify_certs' in conf:
            rule.setdefault('verify_certs', conf.get('verify_certs'))
            rule.setdefault('ca_certs', conf.get('ca_certs'))
            rule.setdefault('client_cert', conf.get('client_cert'))
            rule.setdefault('client_key', conf.get('client_key'))

        # Set HipChat options from global config
        rule.setdefault('hipchat_msg_color', 'red')
        rule.setdefault('hipchat_domain', 'api.hipchat.com')
        rule.setdefault('hipchat_notify', True)
        rule.setdefault('hipchat_from', '')
        rule.setdefault('hipchat_ignore_ssl_errors', False)

        # Make sure we have required options
        if self.required_locals - frozenset(list(rule.keys())):
            raise EAException('Missing required option(s): %s' % (', '.join(self.required_locals - frozenset(list(rule.keys())))))

        if 'include' in rule and type(rule['include']) != list:
            raise EAException('include option must be a list')

        raw_query_key = rule.get('query_key')
        if isinstance(raw_query_key, list):
            if len(raw_query_key) > 1:
                rule['compound_query_key'] = raw_query_key
                rule['query_key'] = ','.join(raw_query_key)
            elif len(raw_query_key) == 1:
                rule['query_key'] = raw_query_key[0]
            else:
                del(rule['query_key'])

        if isinstance(rule.get('aggregation_key'), list):
            rule['compound_aggregation_key'] = rule['aggregation_key']
            rule['aggregation_key'] = ','.join(rule['aggregation_key'])

        if isinstance(rule.get('compare_key'), list):
            rule['compound_compare_key'] = rule['compare_key']
            rule['compare_key'] = ','.join(rule['compare_key'])
        elif 'compare_key' in rule:
            rule['compound_compare_key'] = [rule['compare_key']]
        # Add QK, CK and timestamp to include
        include = rule.get('include', ['*'])
        if 'query_key' in rule:
            include.append(rule['query_key'])
        if 'compound_query_key' in rule:
            include += rule['compound_query_key']
        if 'compound_aggregation_key' in rule:
            include += rule['compound_aggregation_key']
        if 'compare_key' in rule:
            include.append(rule['compare_key'])
        if 'compound_compare_key' in rule:
            include += rule['compound_compare_key']
        if 'top_count_keys' in rule:
            include += rule['top_count_keys']
        include.append(rule['timestamp_field'])
        rule['include'] = list(set(include))

        # Check that generate_kibana_url is compatible with the filters
        if rule.get('generate_kibana_link'):
            for es_filter in rule.get('filter'):
                if es_filter:
                    if 'not' in es_filter:
                        es_filter = es_filter['not']
                    if 'query' in es_filter:
                        es_filter = es_filter['query']
                    if list(es_filter.keys())[0] not in ('term', 'query_string', 'range'):
                        raise EAException(
                            'generate_kibana_link is incompatible with filters other than term, query_string and range.'
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
                                                                             datetime.datetime.now().strftime(
                                                                                 rule.get('index'))))

        if rule.get('scan_entire_timeframe') and not rule.get('timeframe'):
            raise EAException('scan_entire_timeframe can only be used if there is a timeframe specified')

    def load_modules(self, rule, args=None):
        """ Loads things that could be modules. Enhancements, alerts and rule type. """
        # Set match enhancements
        match_enhancements = []
        for enhancement_name in rule.get('match_enhancements', []):
            if enhancement_name in dir(enhancements):
                enhancement = getattr(enhancements, enhancement_name)
            else:
                enhancement = get_module(enhancement_name)
            if not issubclass(enhancement, enhancements.BaseEnhancement):
                raise EAException("Enhancement module %s not a subclass of BaseEnhancement" % enhancement_name)
            match_enhancements.append(enhancement(rule))
        rule['match_enhancements'] = match_enhancements

        # Convert rule type into RuleType object
        if rule['type'] in self.rules_mapping:
            rule['type'] = self.rules_mapping[rule['type']]
        else:
            rule['type'] = get_module(rule['type'])
            if not issubclass(rule['type'], ruletypes.RuleType):
                raise EAException('Rule module %s is not a subclass of RuleType' % (rule['type']))

        # Make sure we have required alert and type options
        reqs = rule['type'].required_options

        if reqs - frozenset(list(rule.keys())):
            raise EAException('Missing required option(s): %s' % (', '.join(reqs - frozenset(list(rule.keys())))))
        # Instantiate rule
        try:
            rule['type'] = rule['type'](rule, args)
        except (KeyError, EAException) as e:
            raise EAException('Error initializing rule %s: %s' % (rule['name'], e)).with_traceback(sys.exc_info()[2])
        # Instantiate alerts only if we're not in debug mode
        # In debug mode alerts are not actually sent so don't bother instantiating them
        if not args or not args.debug:
            rule['alert'] = self.load_alerts(rule, alert_field=rule['alert'])

    def load_alerts(self, rule, alert_field):
        def normalize_config(alert):
            """Alert config entries are either "alertType" or {"alertType": {"key": "data"}}.
            This function normalizes them both to the latter format. """
            if isinstance(alert, str):
                return alert, rule
            elif isinstance(alert, dict):
                name, config = next(iter(list(alert.items())))
                config_copy = copy.copy(rule)
                config_copy.update(config)  # warning, this (intentionally) mutates the rule dict
                return name, config_copy
            else:
                raise EAException()

        def create_alert(alert, alert_config):
            alert_class = self.alerts_mapping.get(alert) or get_module(alert)
            if not issubclass(alert_class, alerts.Alerter):
                raise EAException('Alert module %s is not a subclass of Alerter' % alert)
            missing_options = (rule['type'].required_options | alert_class.required_options) - frozenset(
                alert_config or [])
            if missing_options:
                raise EAException('Missing required option(s): %s' % (', '.join(missing_options)))
            return alert_class(alert_config)

        try:
            if type(alert_field) != list:
                alert_field = [alert_field]

            alert_field = [normalize_config(x) for x in alert_field]
            alert_field = sorted(alert_field, key=lambda a_b: self.alerts_order.get(a_b[0], 1))
            # Convert all alerts into Alerter objects
            alert_field = [create_alert(a, b) for a, b in alert_field]

        except (KeyError, EAException) as e:
            raise EAException('Error initiating alert %s: %s' % (rule['alert'], e)).with_traceback(sys.exc_info()[2])

        return alert_field

    @staticmethod
    def adjust_deprecated_values(rule):
        # From rename of simple HTTP alerter
        if rule.get('type') == 'simple':
            rule['type'] = 'post'
            if 'simple_proxy' in rule:
                rule['http_post_proxy'] = rule['simple_proxy']
            if 'simple_webhook_url' in rule:
                rule['http_post_url'] = rule['simple_webhook_url']
            logging.warning(
                '"simple" alerter has been renamed "post" and comptability may be removed in a future release.')


class FileRulesLoader(RulesLoader):

    # Required global (config.yaml) configuration options for the loader
    required_globals = frozenset(['rules_folder'])

    def get_names(self, conf, use_rule=None):
        # Passing a filename directly can bypass rules_folder and .yaml checks
        if use_rule and os.path.isfile(use_rule):
            return [use_rule]
        rule_folder = conf['rules_folder']
        rule_files = []
        if 'scan_subdirectories' in conf and conf['scan_subdirectories']:
            for root, folders, files in os.walk(rule_folder):
                for filename in files:
                    if use_rule and use_rule != filename:
                        continue
                    if self.is_yaml(filename):
                        rule_files.append(os.path.join(root, filename))
        else:
            for filename in os.listdir(rule_folder):
                fullpath = os.path.join(rule_folder, filename)
                if os.path.isfile(fullpath) and self.is_yaml(filename):
                    rule_files.append(fullpath)
        return rule_files

    def get_hashes(self, conf, use_rule=None):
        rule_files = self.get_names(conf, use_rule)
        rule_mod_times = {}
        for rule_file in rule_files:
            rule_mod_times[rule_file] = self.get_rule_file_hash(rule_file)
        return rule_mod_times

    def get_yaml(self, filename):
        try:
            return yaml_loader(filename)
        except yaml.scanner.ScannerError as e:
            raise EAException('Could not parse file %s: %s' % (filename, e))

    def get_import_rule(self, rule):
        """
        Allow for relative paths to the import rule.
        :param dict rule:
        :return: Path the import rule
        :rtype: str
        """
        if os.path.isabs(rule['import']):
            return rule['import']
        else:
            return os.path.join(os.path.dirname(rule['rule_file']), rule['import'])

    def get_rule_file_hash(self, rule_file):
        rule_file_hash = ''
        if os.path.exists(rule_file):
            with open(rule_file, 'rb') as fh:
                rule_file_hash = hashlib.sha1(fh.read()).digest()
            for import_rule_file in self.import_rules.get(rule_file, []):
                rule_file_hash += self.get_rule_file_hash(import_rule_file)
        return rule_file_hash

    @staticmethod
    def is_yaml(filename):
        return filename.endswith('.yaml') or filename.endswith('.yml')
