# -*- coding: utf-8 -*-
import datetime

from .util import pretty_ts


class BaseEnhancement(object):
    """ Enhancements take a match dictionary object and modify it in some way to
    enhance an alert. These are specified in each rule under the match_enhancements option.
    Generally, the key value pairs in the match module will be contained in the alert body. """

    def __init__(self, rule):
        self.rule = rule

    def process(self, match):
        """ Modify the contents of match, a dictionary, in some way """
        raise NotImplementedError()


class TimeEnhancement(BaseEnhancement):
    def process(self, match):
        match['@timestamp'] = pretty_ts(match['@timestamp'])


class DropMatchException(Exception):
    """ ElastAlert will drop a match if this exception type is raised by an enhancement """
    pass


class CopyFullRuleEnhancement(BaseEnhancement):
    # The enhancement is run against every match
    # The match is passed to the process function where it can be modified in any way
    # ElastAlert will do this for each enhancement linked to a rule
    def process(self, match):
        rule_copy = dict(self.rule)
        rule_copy.pop("type")
        rule_copy.pop("match_enhancements")
        rule_copy.pop("alert")
        keys = []
        for key in list(rule_copy.keys()):
            if isinstance(rule_copy[key], datetime.timedelta) or callable(rule_copy[key]):
                keys.append(key)
        rule_copy["type"] = type(self.rule["type"]).__name__
        match["rule"] = rule_copy


class CopyRuleTypeEnhancement(BaseEnhancement):
    def process(self, match):
        match["rule_type"] = type(self.rule["type"]).__name__
