import requests
from requests import RequestException

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException, elastalert_logger


class LineNotifyAlerter(Alerter):
    """ Created a Line Notify for each alert """
    required_option = frozenset(["linenotify_access_token"])

    def __init__(self, rule):
        super(LineNotifyAlerter, self).__init__(rule)
        self.linenotify_access_token = self.rule.get("linenotify_access_token", None)

    def alert(self, matches):
        body = ''
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        if len(body) > 999:
            body = body[0:900] + '\n *message was cropped according to line notify embed description limits!*'
        # post to Line Notify
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer {}".format(self.linenotify_access_token)
        }
        payload = {
            "message": body
        }
        try:
            response = requests.post("https://notify-api.line.me/api/notify", data=payload, headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Line Notify: %s" % e)
        elastalert_logger.info("Alert sent to Line Notify")

    def get_info(self):
        return {"type": "linenotify", "linenotify_access_token": self.linenotify_access_token}
