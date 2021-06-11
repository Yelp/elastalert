import prometheus_client


class PrometheusWrapper:
    """ Exposes ElastAlert metrics on a Prometheus metrics endpoint.
        Wraps ElastAlerter run_rule and writeback to collect metrics. """

    def __init__(self, client):
        self.prometheus_port = client.prometheus_port
        self.run_rule = client.run_rule
        self.writeback = client.writeback

        client.run_rule = self.metrics_run_rule
        client.writeback = self.metrics_writeback

        # initialize prometheus metrics to be exposed
        self.prom_scrapes = prometheus_client.Counter('elastalert_scrapes', 'Number of scrapes for rule', ['rule_name'])
        self.prom_hits = prometheus_client.Counter('elastalert_hits', 'Number of hits for rule', ['rule_name'])
        self.prom_matches = prometheus_client.Counter('elastalert_matches', 'Number of matches for rule', ['rule_name'])
        self.prom_time_taken = prometheus_client.Counter('elastalert_time_taken', 'Time taken to evaluate rule', ['rule_name'])
        self.prom_alerts_sent = prometheus_client.Counter('elastalert_alerts_sent', 'Number of alerts sent for rule', ['rule_name'])
        self.prom_alerts_not_sent = prometheus_client.Counter('elastalert_alerts_not_sent', 'Number of alerts not sent', ['rule_name'])
        self.prom_errors = prometheus_client.Counter('elastalert_errors', 'Number of errors for rule')
        self.prom_alerts_silenced = prometheus_client.Counter('elastalert_alerts_silenced', 'Number of silenced alerts', ['rule_name'])

    def start(self):
        prometheus_client.start_http_server(self.prometheus_port)

    def metrics_run_rule(self, rule, endtime, starttime=None):
        """ Increment counter every time rule is run """
        try:
            self.prom_scrapes.labels(rule['name']).inc()
        finally:
            return self.run_rule(rule, endtime, starttime)

    def metrics_writeback(self, doc_type, body, rule=None, match_body=None):
        """ Update various prometheus metrics accoording to the doc_type """

        res = self.writeback(doc_type, body, rule, match_body)
        try:
            if doc_type == 'elastalert_status':
                self.prom_hits.labels(body['rule_name']).inc(int(body['hits']))
                self.prom_matches.labels(body['rule_name']).inc(int(body['matches']))
                self.prom_time_taken.labels(body['rule_name']).inc(float(body['time_taken']))
            elif doc_type == 'elastalert':
                if body['alert_sent']:
                    self.prom_alerts_sent.labels(body['rule_name']).inc()
                else:
                    self.prom_alerts_not_sent.labels(body['rule_name']).inc()
            elif doc_type == 'elastalert_error':
                self.prom_errors.inc()
            elif doc_type == 'silence':
                self.prom_alerts_silenced.labels(body['rule_name']).inc()
        finally:
            return res
