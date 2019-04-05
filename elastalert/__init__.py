# -*- coding: utf-8 -*-
import copy
from elasticsearch import Elasticsearch, RequestsHttpConnection


class ElasticSearchClient(Elasticsearch):
    """ Extension of low level :class:`Elasticsearch` client with additional version resolving features """

    def __init__(self, conf):
        """
        :arg conf: es_conn_config dictionary. Ref. :func:`~util.build_es_conn_config`
        """
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
        self._conf = copy.copy(conf)
        self._es_version = None

    @property
    def conf(self):
        """
        Returns the provided es_conn_config used when initializing the class instance.
        """
        return self._conf

    @property
    def es_version(self):
        """
        Returns the reported version from the Elasticsearch server.
        """
        if self._es_version is None:
            self._es_version = self.info()['version']['number']
        return self._es_version

    def is_atleastfive(self):
        """
        Returns True when the Elasticsearch server version >= 5
        """
        return int(self.es_version.split(".")[0]) >= 5

    def is_atleastsix(self):
        """
        Returns True when the Elasticsearch server version >= 6
        """
        return int(self.es_version.split(".")[0]) >= 6

    def is_atleastsixsix(self):
        """
        Returns True when the Elasticsearch server version >= 6.6
        """
        major, minor = map(int, self.es_version.split(".")[:2])
        return major > 6 or (major == 6 and minor >= 6)

    def is_atleastseven(self):
        """
        Returns True when the Elasticsearch server version >= 7
        """
        return int(self.es_version.split(".")[0]) >= 7
