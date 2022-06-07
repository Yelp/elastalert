# -*- coding: utf-8 -*-
import copy
import time

from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection
from elasticsearch.client import _make_path
from elasticsearch.client import query_params
from elasticsearch.exceptions import TransportError


class ElasticSearchClient(Elasticsearch):
    """ Extension of low level :class:`Elasticsearch` client with additional version resolving features """

    def __init__(self, conf):
        """
        :arg conf: es_conn_config dictionary. Ref. :func:`~util.build_es_conn_config`
        """
        super(ElasticSearchClient, self).__init__(host=conf.get('es_host'),
                                                  hosts=conf.get('es_hosts'),
                                                  port=conf['es_port'],
                                                  url_prefix=conf['es_url_prefix'],
                                                  use_ssl=conf['use_ssl'],
                                                  verify_certs=conf['verify_certs'],
                                                  ca_certs=conf['ca_certs'],
                                                  ssl_show_warn=conf['ssl_show_warn'],
                                                  connection_class=RequestsHttpConnection,
                                                  http_auth=conf['http_auth'],
                                                  headers=conf['headers'],
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
            self._es_version = util.get_version_from_cluster_info(self)

        return self._es_version

    def is_atleastseven(self):
        """
        Returns True when the Elasticsearch server version >= 7
        """
        return int(self.es_version.split(".")[0]) >= 7

    def is_atleasteight(self):
        """
        Returns True when the Elasticsearch server version >= 8
        """
        return int(self.es_version.split(".")[0]) >= 8


    def resolve_writeback_index(self, writeback_index, doc_type):
        if doc_type == 'silence':
            return writeback_index + '_silence'
        elif doc_type == 'past_elastalert':
            return writeback_index + '_past'
        elif doc_type == 'elastalert_status':
            return writeback_index + '_status'
        elif doc_type == 'elastalert_error':
            return writeback_index + '_error'
        return writeback_index
