from elastalert.alerts import Alerter
from elastalert.elastalert import EAException

import random


class FailureAlerter(Alerter):
    required_options = set()

    def alert(self, match):
        fail = random.choice([True, False])

        if fail:
            raise EAException('Chosen to fail')

    def get_info(self):
        return {
            'type': 'Failure Alerter'
        }
