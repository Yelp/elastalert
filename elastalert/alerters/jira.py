import datetime
import sys

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.util import (elastalert_logger, lookup_es_key, pretty_ts, ts_now,
                             ts_to_dt, EAException)
from jira.client import JIRA
from jira.exceptions import JIRAError


class JiraFormattedMatchString(BasicMatchString):
    def _add_match_items(self):
        match_items = dict([(x, y) for x, y in list(self.match.items()) if not x.startswith('top_events_')])
        json_blob = self._pretty_print_as_json(match_items)
        preformatted_text = '{{code}}{0}{{code}}'.format(json_blob)
        self.text += preformatted_text


class JiraAlerter(Alerter):
    """ Creates a Jira ticket for each alert """
    required_options = frozenset(['jira_server', 'jira_account_file', 'jira_project', 'jira_issuetype'])

    # Maintain a static set of built-in fields that we explicitly know how to set
    # For anything else, we will do best-effort and try to set a string value
    known_field_list = [
        'jira_account_file',
        'jira_assignee',
        'jira_bump_after_inactivity',
        'jira_bump_in_statuses',
        'jira_bump_not_in_statuses',
        'jira_bump_only',
        'jira_bump_tickets',
        'jira_component',
        'jira_components',
        'jira_description',
        'jira_ignore_in_title',
        'jira_issuetype',
        'jira_label',
        'jira_labels',
        'jira_max_age',
        'jira_priority',
        'jira_project',
        'jira_server',
        'jira_transition_to',
        'jira_watchers',
    ]

    # Some built-in Jira types that can be used as custom fields require special handling
    # Here is a sample of one of them:
    # {"id":"customfield_12807","name":"My Custom Field","custom":true,"orderable":true,"navigable":true,"searchable":true,
    # "clauseNames":["cf[12807]","My Custom Field"],"schema":{"type":"array","items":"string",
    # "custom":"com.atlassian.jira.plugin.system.customfieldtypes:multiselect","customId":12807}}
    # There are likely others that will need to be updated on a case-by-case basis
    custom_string_types_with_special_handling = [
        'com.atlassian.jira.plugin.system.customfieldtypes:multicheckboxes',
        'com.atlassian.jira.plugin.system.customfieldtypes:multiselect',
        'com.atlassian.jira.plugin.system.customfieldtypes:radiobuttons',
    ]

    def __init__(self, rule):
        super(JiraAlerter, self).__init__(rule)
        self.server = self.rule['jira_server']
        self.get_account(self.rule['jira_account_file'])
        self.project = self.rule['jira_project']
        self.issue_type = self.rule['jira_issuetype']

        # Deferred settings refer to values that can only be resolved when a match
        # is found and as such loading them will be delayed until we find a match
        self.deferred_settings = []

        # We used to support only a single component. This allows us to maintain backwards compatibility
        # while also giving the user-facing API a more representative name
        self.components = self.rule.get('jira_components', self.rule.get('jira_component'))

        # We used to support only a single label. This allows us to maintain backwards compatibility
        # while also giving the user-facing API a more representative name
        self.labels = self.rule.get('jira_labels', self.rule.get('jira_label'))

        self.description = self.rule.get('jira_description', '')
        self.assignee = self.rule.get('jira_assignee')
        self.max_age = self.rule.get('jira_max_age', 30)
        self.priority = self.rule.get('jira_priority')
        self.bump_tickets = self.rule.get('jira_bump_tickets', False)
        self.bump_not_in_statuses = self.rule.get('jira_bump_not_in_statuses')
        self.bump_in_statuses = self.rule.get('jira_bump_in_statuses')
        self.bump_after_inactivity = self.rule.get('jira_bump_after_inactivity', 0)
        self.bump_only = self.rule.get('jira_bump_only', False)
        self.transition = self.rule.get('jira_transition_to', False)
        self.watchers = self.rule.get('jira_watchers')
        self.client = None

        if self.bump_in_statuses and self.bump_not_in_statuses:
            msg = 'Both jira_bump_in_statuses (%s) and jira_bump_not_in_statuses (%s) are set.' % \
                  (','.join(self.bump_in_statuses), ','.join(self.bump_not_in_statuses))
            intersection = list(set(self.bump_in_statuses) & set(self.bump_in_statuses))
            if intersection:
                msg = '%s Both have common statuses of (%s). As such, no tickets will ever be found.' % (
                    msg, ','.join(intersection))
            msg += ' This should be simplified to use only one or the other.'
            elastalert_logger.warning(msg)

        self.reset_jira_args()

        try:
            self.client = JIRA(self.server, basic_auth=(self.user, self.password))
            self.get_priorities()
            self.jira_fields = self.client.fields()
            self.get_arbitrary_fields()
        except JIRAError as e:
            # JIRAError may contain HTML, pass along only first 1024 chars
            raise EAException("Error connecting to Jira: %s" % (str(e)[:1024])).with_traceback(sys.exc_info()[2])

        self.set_priority()

    def set_priority(self):
        try:
            if self.priority is not None and self.client is not None:
                self.jira_args['priority'] = {'id': self.priority_ids[self.priority]}
        except KeyError:
            elastalert_logger.error("Priority %s not found. Valid priorities are %s" % (self.priority, list(self.priority_ids.keys())))

    def reset_jira_args(self):
        self.jira_args = {'project': {'key': self.project},
                          'issuetype': {'name': self.issue_type}}

        if self.components:
            # Support single component or list
            if type(self.components) != list:
                self.jira_args['components'] = [{'name': self.components}]
            else:
                self.jira_args['components'] = [{'name': component} for component in self.components]
        if self.labels:
            # Support single label or list
            if type(self.labels) != list:
                self.labels = [self.labels]
            self.jira_args['labels'] = self.labels
        if self.watchers:
            # Support single watcher or list
            if type(self.watchers) != list:
                self.watchers = [self.watchers]
        if self.assignee:
            self.jira_args['assignee'] = {'name': self.assignee}

        self.set_priority()

    def set_jira_arg(self, jira_field, value, fields):
        # Remove the jira_ part.  Convert underscores to spaces
        normalized_jira_field = jira_field[5:].replace('_', ' ').lower()
        # All Jira fields should be found in the 'id' or the 'name' field. Therefore, try both just in case
        for identifier in ['name', 'id']:
            field = next((f for f in fields if normalized_jira_field == f[identifier].replace('_', ' ').lower()), None)
            if field:
                break
        if not field:
            # Log a warning to ElastAlert saying that we couldn't find that type?
            # OR raise and fail to load the alert entirely? Probably the latter...
            raise Exception("Could not find a definition for the jira field '{0}'".format(normalized_jira_field))
        arg_name = field['id']
        # Check the schema information to decide how to set the value correctly
        # If the schema information is not available, raise an exception since we don't know how to set it
        # Note this is only the case for two built-in types, id: issuekey and id: thumbnail
        if not ('schema' in field or 'type' in field['schema']):
            raise Exception("Could not determine schema information for the jira field '{0}'".format(normalized_jira_field))
        arg_type = field['schema']['type']

        # Handle arrays of simple types like strings or numbers
        if arg_type == 'array':
            # As a convenience, support the scenario wherein the user only provides
            # a single value for a multi-value field e.g. jira_labels: Only_One_Label
            if type(value) != list:
                value = [value]
            array_items = field['schema']['items']
            # Simple string types
            if array_items in ['string', 'date', 'datetime']:
                # Special case for multi-select custom types (the Jira metadata says that these are strings, but
                # in reality, they are required to be provided as an object.
                if 'custom' in field['schema'] and field['schema']['custom'] in self.custom_string_types_with_special_handling:
                    self.jira_args[arg_name] = [{'value': v} for v in value]
                else:
                    self.jira_args[arg_name] = value
            elif array_items == 'number':
                self.jira_args[arg_name] = [int(v) for v in value]
            # Also attempt to handle arrays of complex types that have to be passed as objects with an identifier 'key'
            elif array_items == 'option':
                self.jira_args[arg_name] = [{'value': v} for v in value]
            else:
                # Try setting it as an object, using 'name' as the key
                # This may not work, as the key might actually be 'key', 'id', 'value', or something else
                # If it works, great!  If not, it will manifest itself as an API error that will bubble up
                self.jira_args[arg_name] = [{'name': v} for v in value]
        # Handle non-array types
        else:
            # Simple string types
            if arg_type in ['string', 'date', 'datetime']:
                # Special case for custom types (the Jira metadata says that these are strings, but
                # in reality, they are required to be provided as an object.
                if 'custom' in field['schema'] and field['schema']['custom'] in self.custom_string_types_with_special_handling:
                    self.jira_args[arg_name] = {'value': value}
                else:
                    self.jira_args[arg_name] = value
            # Number type
            elif arg_type == 'number':
                self.jira_args[arg_name] = int(value)
            elif arg_type == 'option':
                self.jira_args[arg_name] = {'value': value}
            # Complex type
            else:
                self.jira_args[arg_name] = {'name': value}

    def get_arbitrary_fields(self):
        # Clear jira_args
        self.reset_jira_args()

        for jira_field, value in self.rule.items():
            # If we find a field that is not covered by the set that we are aware of, it means it is either:
            # 1. A built-in supported field in Jira that we don't have on our radar
            # 2. A custom field that a Jira admin has configured
            if jira_field.startswith('jira_') and jira_field not in self.known_field_list and str(value)[:1] != '#':
                self.set_jira_arg(jira_field, value, self.jira_fields)
            if jira_field.startswith('jira_') and jira_field not in self.known_field_list and str(value)[:1] == '#':
                self.deferred_settings.append(jira_field)

    def get_priorities(self):
        """ Creates a mapping of priority index to id. """
        priorities = self.client.priorities()
        self.priority_ids = {}
        for x in range(len(priorities)):
            self.priority_ids[x] = priorities[x].id

    def set_assignee(self, assignee):
        self.assignee = assignee
        if assignee:
            self.jira_args['assignee'] = {'name': assignee}
        elif 'assignee' in self.jira_args:
            self.jira_args.pop('assignee')

    def find_existing_ticket(self, matches):
        # Default title, get stripped search version
        if 'alert_subject' not in self.rule:
            title = self.create_default_title(matches, True)
        else:
            title = self.create_title(matches)

        if 'jira_ignore_in_title' in self.rule:
            title = title.replace(matches[0].get(self.rule['jira_ignore_in_title'], ''), '')

        # This is necessary for search to work. Other special characters and dashes
        # directly adjacent to words appear to be ok
        title = title.replace(' - ', ' ')
        title = title.replace('\\', '\\\\')

        date = (datetime.datetime.now() - datetime.timedelta(days=self.max_age)).strftime('%Y-%m-%d')
        jql = 'project=%s AND summary~"%s" and created >= "%s"' % (self.project, title, date)
        if self.bump_in_statuses:
            jql = '%s and status in (%s)' % (jql, ','.join(["\"%s\"" % status if ' ' in status else status for status
                                                            in self.bump_in_statuses]))
        if self.bump_not_in_statuses:
            jql = '%s and status not in (%s)' % (jql, ','.join(["\"%s\"" % status if ' ' in status else status
                                                                for status in self.bump_not_in_statuses]))
        try:
            issues = self.client.search_issues(jql)
        except JIRAError as e:
            elastalert_logger.exception("Error while searching for Jira ticket using jql '%s': %s" % (jql, e))
            return None

        if len(issues):
            return issues[0]

    def comment_on_ticket(self, ticket, match):
        text = str(JiraFormattedMatchString(self.rule, match))
        timestamp = pretty_ts(lookup_es_key(match, self.rule['timestamp_field']))
        comment = "This alert was triggered again at %s\n%s" % (timestamp, text)
        self.client.add_comment(ticket, comment)

    def transition_ticket(self, ticket):
        transitions = self.client.transitions(ticket)
        for t in transitions:
            if t['name'] == self.transition:
                self.client.transition_issue(ticket, t['id'])

    def alert(self, matches):
        # Reset arbitrary fields to pick up changes
        self.get_arbitrary_fields()
        if len(self.deferred_settings) > 0:
            fields = self.client.fields()
            for jira_field in self.deferred_settings:
                value = lookup_es_key(matches[0], self.rule[jira_field][1:])
                self.set_jira_arg(jira_field, value, fields)

        title = self.create_title(matches)

        if self.bump_tickets:
            ticket = self.find_existing_ticket(matches)
            if ticket:
                inactivity_datetime = ts_now() - datetime.timedelta(days=self.bump_after_inactivity)
                if ts_to_dt(ticket.fields.updated) >= inactivity_datetime:
                    if self.pipeline is not None:
                        self.pipeline['jira_ticket'] = None
                        self.pipeline['jira_server'] = self.server
                    return None
                elastalert_logger.info('Commenting on existing ticket %s' % (ticket.key))
                for match in matches:
                    try:
                        self.comment_on_ticket(ticket, match)
                    except JIRAError as e:
                        elastalert_logger.exception("Error while commenting on ticket %s: %s" % (ticket, e))
                    if self.labels:
                        for label in self.labels:
                            try:
                                ticket.fields.labels.append(label)
                            except JIRAError as e:
                                elastalert_logger.exception("Error while appending labels to ticket %s: %s" % (ticket, e))
                if self.transition:
                    elastalert_logger.info('Transitioning existing ticket %s' % (ticket.key))
                    try:
                        self.transition_ticket(ticket)
                    except JIRAError as e:
                        elastalert_logger.exception("Error while transitioning ticket %s: %s" % (ticket, e))

                if self.pipeline is not None:
                    self.pipeline['jira_ticket'] = ticket
                    self.pipeline['jira_server'] = self.server
                return None
        if self.bump_only:
            return None

        self.jira_args['summary'] = title
        self.jira_args['description'] = self.create_alert_body(matches)

        try:
            self.issue = self.client.create_issue(**self.jira_args)

            # You can not add watchers on initial creation. Only as a follow-up action
            if self.watchers:
                for watcher in self.watchers:
                    try:
                        self.client.add_watcher(self.issue.key, watcher)
                    except Exception as ex:
                        # Re-raise the exception, preserve the stack-trace, and give some
                        # context as to which watcher failed to be added
                        raise Exception(
                            "Exception encountered when trying to add '{0}' as a watcher. Does the user exist?\n{1}" .format(
                                watcher,
                                ex
                            )).with_traceback(sys.exc_info()[2])

        except JIRAError as e:
            raise EAException("Error creating Jira ticket using jira_args (%s): %s" % (self.jira_args, e))
        elastalert_logger.info("Opened Jira ticket: %s" % (self.issue))

        if self.pipeline is not None:
            self.pipeline['jira_ticket'] = self.issue
            self.pipeline['jira_server'] = self.server

    def create_alert_body(self, matches):
        body = self.description + '\n'
        body += self.get_aggregation_summary_text(matches)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(JiraFormattedMatchString(self.rule, match))
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text(self, matches):
        text = super(JiraAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = '{{noformat}}{0}{{noformat}}'.format(text)
        return text

    def create_default_title(self, matches, for_search=False):
        # If there is a query_key, use that in the title

        if 'query_key' in self.rule and lookup_es_key(matches[0], self.rule['query_key']):
            title = 'ElastAlert: %s matched %s' % (lookup_es_key(matches[0], self.rule['query_key']), self.rule['name'])
        else:
            title = 'ElastAlert: %s' % (self.rule['name'])

        if for_search:
            return title

        timestamp = matches[0].get(self.rule['timestamp_field'])
        if timestamp:
            title += ' - %s' % (pretty_ts(timestamp, self.rule.get('use_local_time')))

        # Add count for spikes
        count = matches[0].get('spike_count')
        if count:
            title += ' - %s+ events' % (count)

        return title

    def get_info(self):
        return {'type': 'jira'}
