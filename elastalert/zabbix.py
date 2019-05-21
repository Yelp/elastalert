from alerts import Alerter  # , BasicMatchString
import logging
from pyzabbix.api import ZabbixAPI
from pyzabbix import ZabbixSender, ZabbixMetric
from datetime import datetime


class ZabbixClient(ZabbixAPI):

    def __init__(self, url='http://localhost', use_authenticate=False, user='Admin', password='zabbix', sender_host='localhost',
                 sender_port=10051):
        self.url = url
        self.use_authenticate = use_authenticate
        self.sender_host = sender_host
        self.sender_port = sender_port
        self.metrics_chunk_size = 200
        self.aggregated_metrics = []
        self.logger = logging.getLogger(self.__class__.__name__)
        super(ZabbixClient, self).__init__(url=self.url, use_authenticate=self.use_authenticate, user=user, password=password)

    def send_metric(self, hostname, key, data):
        zm = ZabbixMetric(hostname, key, data)
        if self.send_aggregated_metrics:

            self.aggregated_metrics.append(zm)
            if len(self.aggregated_metrics) > self.metrics_chunk_size:
                self.logger.info("Sending: %s metrics" % (len(self.aggregated_metrics)))
                try:
                    ZabbixSender(zabbix_server=self.sender_host, zabbix_port=self.sender_port).send(self.aggregated_metrics)
                    self.aggregated_metrics = []
                except Exception as e:
                    self.logger.exception(e)
                    pass
        else:
            try:
                ZabbixSender(zabbix_server=self.sender_host, zabbix_port=self.sender_port).send(zm)
            except Exception as e:
                self.logger.exception(e)
                pass


class ZabbixAlerter(Alerter):

    # By setting required_options to a set of strings
    # You can ensure that the rule config file specifies all
    # of the options. Otherwise, ElastAlert will throw an exception
    # when trying to load the rule.
    required_options = frozenset(['zbx_sender_host', 'zbx_sender_port', 'zbx_host', 'zbx_key'])

    def __init__(self, *args):
        super(ZabbixAlerter, self).__init__(*args)

        self.zbx_sender_host = self.rule.get('zbx_sender_host', 'localhost')
        self.zbx_sender_port = self.rule.get('zbx_sender_port', 10051)
        self.zbx_host = self.rule.get('zbx_host')
        self.zbx_key = self.rule.get('zbx_key')

    # Alert is called
    def alert(self, matches):

        # Matches is a list of match dictionaries.
        # It contains more than one match when the alert has
        # the aggregation option set
        zm = []
        for match in matches:
            ts_epoch = int(datetime.strptime(match['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime('%s'))
            zm.append(ZabbixMetric(host=self.zbx_host, key=self.zbx_key, value=1, clock=ts_epoch))

        ZabbixSender(zabbix_server=self.zbx_sender_host, zabbix_port=self.zbx_sender_port).send(zm)

    # get_info is called after an alert is sent to get data that is written back
    # to Elasticsearch in the field "alert_info"
    # It should return a dict of information relevant to what the alert does
    def get_info(self):
        return {'type': 'zabbix Alerter'}
