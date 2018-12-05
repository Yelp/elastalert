import re
import yaml

from dateutil import tz
from elastalert.ruletypes import RuleType
from elastalert.util import ts_to_dt, elastalert_logger


class SyslogCheckerRule(RuleType):
    required_options = set(['regex_file'])

    def load_regex_rules(self):
        rules = None
        try:
            with open(self.rules['regex_file'], 'r') as f:
                rules = yaml.load(f)
                elastalert_logger.debug('Syslog: Loaded {} rules from file'.format(len(rules)))
        except yaml.YAMLError as ex:
            elastalert_logger.warn('Error loading yaml rules file: {}'.format(str(ex)))
        return rules

    def to_localtz(self, ts):
	return ts.astimezone(tz.tzlocal())

    def add_data(self, data):
        regex_rules = self.load_regex_rules()
        if not regex_rules:
            return
        # check if any of the datapoints match any of the defined regexs
        matched = []
        for point in data:
	    if 'syslog_message' not in point or 'syslog_severity' not in point or 'syslog_hostname' not in point:
		continue
            for rule in regex_rules:
                r = re.compile(rule['regex'])
                m = r.match(point['syslog_message'])
                if not m:
                    continue
                elastalert_logger.debug('Found a match for rule: {}: {}'.format(rule['id'], rule['name']))
                point.update(m.groupdict())
		point.setdefault('entity', 'None')
                sev = rule.get('severity')
                if sev:
                    point['syslog_severity'] = sev
                # convert timestamp to RFC3339
                dt = self.to_localtz(ts_to_dt(point['@timestamp']))
                point['timestamp'] = dt.isoformat()
		point['id'] = rule['id']
                point['name'] = rule['name']
		match = '{}:{}:{}'.format(
		    point['name'],
		    point['syslog_hostname'],
		    point['entity']
		)
		if match not in matched:
                    self.add_match(point)
                    matched.append(match)
