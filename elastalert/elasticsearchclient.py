# -*- coding: utf-8 -*-
from elasticsearch import Elasticsearch, RequestsHttpConnection


class ElasticSearchClient(Elasticsearch):

    def __init__(self, conf):
        super(ElasticSearchClient, self).__init__(host=conf['es_host'],
                                                  port=conf['es_port'],
                                                  url_prefix=conf['es_url_prefix'],
                                                  use_ssl=conf['use_ssl'],
                                                  verify_certs=conf['verify_certs'],
                                                  ca_certs=conf['ca_certs'],
                                                  connection_class=RequestsHttpConnection,
                                                  http_auth=conf['http_auth'],
                                                  timeout=conf['es_conn_timeout'],
                                                  send_get_body_as=conf['send_get_body_as'],
                                                  client_cert=conf['client_cert'],
                                                  client_key=conf['client_key'])
        self._conf = conf
        self._es_version = None

    @property
    def conf(self):
        return self._conf

    @property
    def es_version(self):
        if self._es_version is None:
            self._es_version = self.info()['version']['number']
        return self._es_version

    def is_atleastfive(self):
        return int(self.es_version.split(".")[0]) >= 5

    def is_atleastsix(self):
        return int(self.es_version.split(".")[0]) >= 6

    def is_atleastsixsix(self):
        major, minor = map(int, self.es_version.split(".")[:2])
        return major > 6 or (major == 6 and minor >= 6)

    def is_atleastseven(self):
        return int(self.es_version.split(".")[0]) >= 7
