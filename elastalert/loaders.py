# -*- coding: utf-8 -*-
import copy
import datetime
import hashlib
import os
import sys

import jsonschema
import yaml
import yaml.scanner
from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import Template

import elastalert.alerters.alerta
import elastalert.alerters.chatwork
import elastalert.alerters.command
import elastalert.alerters.datadog
import elastalert.alerters.debug
import elastalert.alerters.dingtalk
import elastalert.alerters.discord
import elastalert.alerters.exotel
import elastalert.alerters.gitter
import elastalert.alerters.googlechat
import elastalert.alerters.httppost
import elastalert.alerters.line
import elastalert.alerters.pagertree
import elastalert.alerters.rocketchat
import elastalert.alerters.servicenow
import elastalert.alerters.ses
import elastalert.alerters.stomp
import elastalert.alerters.telegram
import elastalert.alerters.thehive
import elastalert.alerters.twilio
import elastalert.alerters.victorops
from elastalert import alerts
from elastalert import enhancements
from elastalert import ruletypes
from elastalert.alerters.email import EmailAlerter
from elastalert.alerters.jira import JiraAlerter
from elastalert.alerters.mattermost import MattermostAlerter
from elastalert.alerters.opsgenie import OpsGenieAlerter
from elastalert.alerters.pagerduty import PagerDutyAlerter
from elastalert.alerters.slack import SlackAlerter
from elastalert.alerters.sns import SnsAlerter
from elastalert.alerters.teams import MsTeamsAlerter
from elastalert.alerters.zabbix import ZabbixAlerter
from elastalert.util import dt_to_ts
from elastalert.util import dt_to_ts_with_format
from elastalert.util import dt_to_unix
from elastalert.util import dt_to_unixms
from elastalert.util import EAException
from elastalert.util import elastalert_logger
from elastalert.util import get_module
from elastalert.util import ts_to_dt
from elastalert.util import ts_to_dt_with_format
from elastalert.util import unix_to_dt
from elastalert.util import unixms_to_dt
from elastalert.yaml import read_yaml


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
        'email': EmailAlerter,
        'jira': JiraAlerter,
        'opsgenie': OpsGenieAlerter,
        'stomp': elastalert.alerters.stomp.StompAlerter,
        'debug': elastalert.alerters.debug.DebugAlerter,
        'command': elastalert.alerters.command.CommandAlerter,
        'sns': SnsAlerter,
        'ms_teams': MsTeamsAlerter,
        'slack': SlackAlerter,
        'mattermost': MattermostAlerter,
        'pagerduty': PagerDutyAlerter,
        'exotel': elastalert.alerters.exotel.ExotelAlerter,
        'twilio': elastalert.alerters.twilio.TwilioAlerter,
        'victorops': elastalert.alerters.victorops.VictorOpsAlerter,
        'telegram': elastalert.alerters.telegram.TelegramAlerter,
        'googlechat': elastalert.alerters.googlechat.GoogleChatAlerter,
        'gitter': elastalert.alerters.gitter.GitterAlerter,
        'servicenow': elastalert.alerters.servicenow.ServiceNowAlerter,
        'alerta': elastalert.alerters.alerta.AlertaAlerter,
        'post': elastalert.alerters.httppost.HTTPPostAlerter,
        'pagertree': elastalert.alerters.pagertree.PagerTreeAlerter,
        'linenotify': elastalert.alerters.line.LineNotifyAlerter,
        'hivealerter': elastalert.alerters.thehive.HiveAlerter,
        'zabbix': ZabbixAlerter,
        'discord': elastalert.alerters.discord.DiscordAlerter,
        'dingtalk': elastalert.alerters.dingtalk.DingTalkAlerter,
        'chatwork': elastalert.alerters.chatwork.ChatworkAlerter,
        'datadog': elastalert.alerters.datadog.DatadogAlerter,
        'ses': elastalert.alerters.ses.SesAlerter,
        'rocketchat': elastalert.alerters.rocketchat.RocketChatAlerter
    }

    # A partial ordering of alert types. Relative order will be preserved in the resulting alerts list
    # For example, jira goes before email so the ticket # will be added to the resulting email.
    alerts_order = {
        'jira': 0,
        'email': 1
    }

    base_config = {}

    jinja_environment = Environment(loader=FileSystemLoader(""))

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
                    elastalert_logger.error('Invalid rule file skipped: %s' % rule_file)
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
        files_to_import = []
        while True:
            loaded = self.get_yaml(filename)

            # Special case for merging filters - if both files specify a filter merge (AND) them
            if 'filter' in rule and 'filter' in loaded:
                rule['filter'] = loaded['filter'] + rule['filter']

            loaded.update(rule)
            rule = loaded
            if 'import' in rule:
                # add all of the files to load into the load queue
                files_to_import += self.get_import_rule(rule)
                del (rule['import'])  # or we could go on forever!
            if len(files_to_import) > 0:
                # set the next file to load
                next_file_to_import = files_to_import.pop()
                rules = self.import_rules.get(filename, [])
                rules.append(next_file_to_import)
                self.import_rules[filename] = rules
                filename = next_file_to_import
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
        rule.setdefault('jinja_root_name', "_data")
        rule.setdefault('query_timezone', "")

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
                    elastalert_logger.warning('Did you mean to use %s in the index? '
                                              'The index will be formatted like %s' % (token,
                                                                                       datetime.datetime.now().strftime(
                                                                                           rule.get('index'))))

        if rule.get('scan_entire_timeframe') and not rule.get('timeframe'):
            raise EAException('scan_entire_timeframe can only be used if there is a timeframe specified')

        # Compile Jinja Template
        if rule.get('alert_text_type') == 'alert_text_jinja':
            jinja_template_path = rule.get('jinja_template_path')
            if jinja_template_path:
                rule["jinja_template"] = self.jinja_environment.get_or_select_template(jinja_template_path)
            else:
                rule["jinja_template"] = Template(str(rule.get('alert_text', '')))

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
            elastalert_logger.warning(
                '"simple" alerter has been renamed "post" and comptability may be removed in a future release.')


class FileRulesLoader(RulesLoader):

    # Required global (config.yaml) configuration options for the loader
    required_globals = frozenset(['rules_folder'])

    def get_names(self, conf, use_rule=None):
        # Passing a filename directly can bypass rules_folder and .yaml checks
        if use_rule and os.path.isfile(use_rule):
            return [use_rule]

        # In case of a bad type, convert string to list:
        rule_folders = conf['rules_folder'] if isinstance(conf['rules_folder'], list) else [conf['rules_folder']]
        rule_files = []
        if 'scan_subdirectories' in conf and conf['scan_subdirectories']:
            for ruledir in rule_folders:
                for root, folders, files in os.walk(ruledir, followlinks=True):
                    # Openshift/k8s configmap fix for ..data and ..2021_05..date directories that loop with os.walk()
                    folders[:] = [d for d in folders if not d.startswith('..')]
                    for filename in files:
                        if use_rule and use_rule != filename:
                            continue
                        if self.is_yaml(filename):
                            rule_files.append(os.path.join(root, filename))
        else:
            for ruledir in rule_folders:
                if not os.path.isdir(ruledir):
                    continue
                for file in os.scandir(ruledir):
                    fullpath = os.path.join(ruledir, file.name)
                    if os.path.isfile(fullpath) and self.is_yaml(file.name):
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
            return read_yaml(filename)
        except yaml.scanner.ScannerError as e:
            raise EAException('Could not parse file %s: %s' % (filename, e))

    def get_import_rule(self, rule):
        """
        Allow for relative paths to the import rule.
        :param dict rule:
        :return: Path the import rule
        :rtype: str
        """
        rule_imports = rule['import']
        if type(rule_imports) is str:
            rule_imports = [rule_imports]
        expanded_imports = []
        for rule_import in rule_imports:
            if os.path.isabs(rule_import):
                expanded_imports.append(rule_import)
            else:
                expanded_imports.append(os.path.join(os.path.dirname(rule['rule_file']), rule_import))
        return expanded_imports

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
