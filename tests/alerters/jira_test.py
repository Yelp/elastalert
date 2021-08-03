import datetime
import logging
import pytest

from jira import JIRAError
from unittest import mock

from elastalert.alerters.jira import JiraFormattedMatchString, JiraAlerter
from elastalert.util import ts_now
from tests.alerts_test import mock_rule


def test_jira_formatted_match_string(ea):
    match = {'foo': {'bar': ['one', 2, 'three']}, 'top_events_poof': 'phew'}
    alert_text = str(JiraFormattedMatchString(ea.rules[0], match))
    tab = 4 * ' '
    expected_alert_text_snippet = '{code}{\n' \
        + tab + '"foo": {\n' \
        + 2 * tab + '"bar": [\n' \
        + 3 * tab + '"one",\n' \
        + 3 * tab + '2,\n' \
        + 3 * tab + '"three"\n' \
        + 2 * tab + ']\n' \
        + tab + '}\n' \
        + '}{code}'
    assert expected_alert_text_snippet in alert_text


def test_jira(caplog):
    caplog.set_level(logging.INFO)
    description_txt = "Description stuff goes here like a runbook link."
    rule = {
        'name': 'test alert',
        'jira_account_file': 'jirafile',
        'type': mock_rule(),
        'jira_project': 'testproject',
        'jira_priority': 0,
        'jira_issuetype': 'testtype',
        'jira_server': 'jiraserver',
        'jira_label': 'testlabel',
        'jira_component': 'testcomponent',
        'jira_description': description_txt,
        'jira_watchers': ['testwatcher1', 'testwatcher2'],
        'timestamp_field': '@timestamp',
        'alert_subject': 'Issue {0} occurred at {1}',
        'alert_subject_args': ['test_term', '@timestamp'],
        'rule_file': '/tmp/foo.yaml'
    }

    mock_priority = mock.Mock(id='5')

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []
        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    expected = [
        mock.call('jiraserver', basic_auth=('jirauser', 'jirapassword')),
        mock.call().priorities(),
        mock.call().fields(),
        mock.call().create_issue(
            issuetype={'name': 'testtype'},
            priority={'id': '5'},
            project={'key': 'testproject'},
            labels=['testlabel'],
            components=[{'name': 'testcomponent'}],
            description=mock.ANY,
            summary='Issue test_value occurred at 2014-10-31T00:00:00',
        ),
        mock.call().add_watcher(mock.ANY, 'testwatcher1'),
        mock.call().add_watcher(mock.ANY, 'testwatcher2'),
    ]

    # We don't care about additional calls to mock_jira, such as __str__
    assert mock_jira.mock_calls[:6] == expected
    assert mock_jira.mock_calls[3][2]['description'].startswith(description_txt)
    user, level, message = caplog.record_tuples[0]
    assert 'elastalert' == user
    assert logging.INFO == level
    assert 'pened Jira ticket: ' in message

    # Search called if jira_bump_tickets
    rule['jira_bump_tickets'] = True
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = []
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    expected.insert(3, mock.call().search_issues(mock.ANY))
    assert mock_jira.mock_calls == expected

    # Remove a field if jira_ignore_in_title set
    rule['jira_ignore_in_title'] = 'test_term'
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = []
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    assert 'test_value' not in mock_jira.mock_calls[3][1][0]

    # Issue is still created if search_issues throws an exception
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.side_effect = JIRAError
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    assert mock_jira.mock_calls == expected
    user, level, message = caplog.record_tuples[3]
    assert 'elastalert' in user
    assert logging.ERROR == level
    assert 'Error while searching for Jira ticket using jql' in message

    # Only bump after 3d of inactivity
    rule['jira_bump_after_inactivity'] = 3
    mock_issue = mock.Mock()

    # Check ticket is bumped if it is updated 4 days ago
    mock_issue.fields.updated = str(ts_now() - datetime.timedelta(days=4))
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = [mock_issue]
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        # Check add_comment is called
        assert len(mock_jira.mock_calls) == 5
        assert '().add_comment' == mock_jira.mock_calls[4][0]

    # Check ticket is bumped is not bumped if ticket is updated right now
    mock_issue.fields.updated = str(ts_now())
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = [mock_issue]
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        # Only 4 calls for mock_jira since add_comment is not called
        assert len(mock_jira.mock_calls) == 4

        # Test match resolved values
        rule = {
            'name': 'test alert',
            'jira_account_file': 'jirafile',
            'type': mock_rule(),
            'owner': 'the_owner',
            'jira_project': 'testproject',
            'jira_issuetype': 'testtype',
            'jira_server': 'jiraserver',
            'jira_label': 'testlabel',
            'jira_component': 'testcomponent',
            'jira_description': "DESC",
            'jira_watchers': ['testwatcher1', 'testwatcher2'],
            'timestamp_field': '@timestamp',
            'jira_affected_user': "#gmail.the_user",
            'rule_file': '/tmp/foo.yaml'
        }
        mock_issue = mock.Mock()
        mock_issue.fields.updated = str(ts_now() - datetime.timedelta(days=4))
        mock_fields = [
            {'name': 'affected user', 'id': 'affected_user_id', 'schema': {'type': 'string'}}
        ]
        with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
                mock.patch('elastalert.alerts.read_yaml') as mock_open:
            mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
            mock_jira.return_value = mock.Mock()
            mock_jira.return_value.search_issues.return_value = [mock_issue]
            mock_jira.return_value.fields.return_value = mock_fields
            mock_jira.return_value.priorities.return_value = [mock_priority]
            alert = JiraAlerter(rule)
            alert.alert([{'gmail.the_user': 'jdoe', '@timestamp': '2014-10-31T00:00:00'}])
            assert mock_jira.mock_calls[4][2]['affected_user_id'] == "jdoe"


def test_jira_arbitrary_field_support():
    description_txt = "Description stuff goes here like a runbook link."
    rule = {
        'name': 'test alert',
        'jira_account_file': 'jirafile',
        'type': mock_rule(),
        'owner': 'the_owner',
        'jira_project': 'testproject',
        'jira_issuetype': 'testtype',
        'jira_server': 'jiraserver',
        'jira_label': 'testlabel',
        'jira_component': 'testcomponent',
        'jira_description': description_txt,
        'jira_watchers': ['testwatcher1', 'testwatcher2'],
        'jira_arbitrary_reference_string_field': '$owner$',
        'jira_arbitrary_string_field': 'arbitrary_string_value',
        'jira_arbitrary_string_array_field': ['arbitrary_string_value1', 'arbitrary_string_value2'],
        'jira_arbitrary_string_array_field_provided_as_single_value': 'arbitrary_string_value_in_array_field',
        'jira_arbitrary_number_field': 1,
        'jira_arbitrary_number_array_field': [2, 3],
        'jira_arbitrary_number_array_field_provided_as_single_value': 1,
        'jira_arbitrary_complex_field': 'arbitrary_complex_value',
        'jira_arbitrary_complex_array_field': ['arbitrary_complex_value1', 'arbitrary_complex_value2'],
        'jira_arbitrary_complex_array_field_provided_as_single_value': 'arbitrary_complex_value_in_array_field',
        'timestamp_field': '@timestamp',
        'alert_subject': 'Issue {0} occurred at {1}',
        'alert_subject_args': ['test_term', '@timestamp'],
        'rule_file': '/tmp/foo.yaml'
    }

    mock_priority = mock.MagicMock(id='5')

    mock_fields = [
        {'name': 'arbitrary reference string field', 'id': 'arbitrary_reference_string_field', 'schema': {'type': 'string'}},
        {'name': 'arbitrary string field', 'id': 'arbitrary_string_field', 'schema': {'type': 'string'}},
        {'name': 'arbitrary string array field', 'id': 'arbitrary_string_array_field', 'schema': {'type': 'array', 'items': 'string'}},
        {
            'name': 'arbitrary string array field provided as single value',
            'id': 'arbitrary_string_array_field_provided_as_single_value',
            'schema': {'type': 'array', 'items': 'string'}
        },
        {'name': 'arbitrary number field', 'id': 'arbitrary_number_field', 'schema': {'type': 'number'}},
        {'name': 'arbitrary number array field', 'id': 'arbitrary_number_array_field', 'schema': {'type': 'array', 'items': 'number'}},
        {
            'name': 'arbitrary number array field provided as single value',
            'id': 'arbitrary_number_array_field_provided_as_single_value',
            'schema': {'type': 'array', 'items': 'number'}
        },
        {'name': 'arbitrary complex field', 'id': 'arbitrary_complex_field', 'schema': {'type': 'ArbitraryType'}},
        {
            'name': 'arbitrary complex array field',
            'id': 'arbitrary_complex_array_field',
            'schema': {'type': 'array', 'items': 'ArbitraryType'}
        },
        {
            'name': 'arbitrary complex array field provided as single value',
            'id': 'arbitrary_complex_array_field_provided_as_single_value',
            'schema': {'type': 'array', 'items': 'ArbitraryType'}
        },
    ]

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = mock_fields
        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    expected = [
        mock.call('jiraserver', basic_auth=('jirauser', 'jirapassword')),
        mock.call().priorities(),
        mock.call().fields(),
        mock.call().create_issue(
            issuetype={'name': 'testtype'},
            project={'key': 'testproject'},
            labels=['testlabel'],
            components=[{'name': 'testcomponent'}],
            description=mock.ANY,
            summary='Issue test_value occurred at 2014-10-31T00:00:00',
            arbitrary_reference_string_field='the_owner',
            arbitrary_string_field='arbitrary_string_value',
            arbitrary_string_array_field=['arbitrary_string_value1', 'arbitrary_string_value2'],
            arbitrary_string_array_field_provided_as_single_value=['arbitrary_string_value_in_array_field'],
            arbitrary_number_field=1,
            arbitrary_number_array_field=[2, 3],
            arbitrary_number_array_field_provided_as_single_value=[1],
            arbitrary_complex_field={'name': 'arbitrary_complex_value'},
            arbitrary_complex_array_field=[{'name': 'arbitrary_complex_value1'}, {'name': 'arbitrary_complex_value2'}],
            arbitrary_complex_array_field_provided_as_single_value=[{'name': 'arbitrary_complex_value_in_array_field'}],
        ),
        mock.call().add_watcher(mock.ANY, 'testwatcher1'),
        mock.call().add_watcher(mock.ANY, 'testwatcher2'),
    ]

    # We don't care about additional calls to mock_jira, such as __str__
    assert mock_jira.mock_calls[:6] == expected
    assert mock_jira.mock_calls[3][2]['description'].startswith(description_txt)

    # Reference an arbitrary string field that is not defined on the Jira server
    rule['jira_nonexistent_field'] = 'nonexistent field value'

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = mock_fields

        with pytest.raises(Exception) as exception:
            alert = JiraAlerter(rule)
            alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        assert "Could not find a definition for the jira field 'nonexistent field'" in str(exception)

    del rule['jira_nonexistent_field']

    # Reference a watcher that does not exist
    rule['jira_watchers'] = 'invalid_watcher'

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = mock_fields

        # Cause add_watcher to raise, which most likely means that the user did not exist
        mock_jira.return_value.add_watcher.side_effect = Exception()

        with pytest.raises(Exception) as exception:
            alert = JiraAlerter(rule)
            alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        assert "Exception encountered when trying to add 'invalid_watcher' as a watcher. Does the user exist?" in str(exception)


def test_jira_getinfo():
    description_txt = "Description stuff goes here like a runbook link."
    rule = {
        'name': 'test alert',
        'jira_account_file': 'jirafile',
        'type': mock_rule(),
        'jira_project': 'testproject',
        'jira_priority': 0,
        'jira_issuetype': 'testtype',
        'jira_server': 'jiraserver',
        'jira_label': 'testlabel',
        'jira_component': 'testcomponent',
        'jira_description': description_txt,
        'jira_watchers': ['testwatcher1', 'testwatcher2'],
        'timestamp_field': '@timestamp',
        'alert_subject': 'Issue {0} occurred at {1}',
        'alert_subject_args': ['test_term', '@timestamp'],
        'rule_file': '/tmp/foo.yaml'
    }

    mock_priority = mock.Mock(id='5')

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []
        alert = JiraAlerter(rule)

    expected_data = {
        'type': 'jira'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


def test_jira_set_priority(caplog):
    description_txt = "Description stuff goes here like a runbook link."
    rule = {
        'name': 'test alert',
        'jira_account_file': 'jirafile',
        'type': mock_rule(),
        'jira_project': 'testproject',
        'jira_priority': 0,
        'jira_issuetype': 'testtype',
        'jira_server': 'jiraserver',
        'jira_description': description_txt,
        'jira_assignee': 'testuser',
        'timestamp_field': '@timestamp',
        'alert_subject': 'Issue {0} occurred at {1}',
        'alert_subject_args': ['test_term', '@timestamp'],
        'rule_file': '/tmp/foo.yaml'
    }
    with mock.patch('elastalert.alerters.jira.JIRA'), \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        alert = JiraAlerter(rule)
        alert.set_priority

    assert ('elastalert', logging.ERROR,
            'Priority 0 not found. Valid priorities are []') == caplog.record_tuples[0]
    assert ('elastalert', logging.ERROR,
            'Priority 0 not found. Valid priorities are []') == caplog.record_tuples[1]
