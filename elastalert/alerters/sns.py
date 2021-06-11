import boto3

from elastalert.alerts import Alerter
from elastalert.util import elastalert_logger, EAException


class SnsAlerter(Alerter):
    """ Send alert using AWS SNS service """
    required_options = frozenset(['sns_topic_arn'])

    def __init__(self, *args):
        super(SnsAlerter, self).__init__(*args)
        self.sns_topic_arn = self.rule.get('sns_topic_arn', None)
        self.sns_aws_access_key_id = self.rule.get('sns_aws_access_key_id')
        self.sns_aws_secret_access_key = self.rule.get('sns_aws_secret_access_key')
        self.sns_aws_region = self.rule.get('sns_aws_region', 'us-east-1')
        self.profile = self.rule.get('sns_aws_profile', None)

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])
        return subject

    def alert(self, matches):
        body = self.create_alert_body(matches)

        try:
            if self.profile is None:
                session = boto3.Session(
                    aws_access_key_id=self.sns_aws_access_key_id,
                    aws_secret_access_key=self.sns_aws_access_key_id,
                    region_name=self.sns_aws_region
                )
            else:
                session = boto3.Session(profile_name=self.profile)

            sns_client = session.client('sns')
            sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Message=body,
                Subject=self.create_title(matches)
            )
        except Exception as e:
            raise EAException("Error sending Amazon SNS: %s" % e)
        elastalert_logger.info("Sent Amazon SNS notification to %s" % (self.sns_topic_arn))

    def get_info(self):
        return {'type': 'sns'}
