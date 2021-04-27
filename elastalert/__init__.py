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
        super(ElasticSearchClient, self).__init__(host=conf['es_host'],
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
            for retry in range(3):
                try:
                    self._es_version = self.info()['version']['number']
                    break
                except TransportError:
                    if retry == 2:
                        raise
                    time.sleep(3)
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

    def is_atleastsixtwo(self):
        """
        Returns True when the Elasticsearch server version >= 6.2
        """
        major, minor = list(map(int, self.es_version.split(".")[:2]))
        return major > 6 or (major == 6 and minor >= 2)

    def is_atleastsixsix(self):
        """
        Returns True when the Elasticsearch server version >= 6.6
        """
        major, minor = list(map(int, self.es_version.split(".")[:2]))
        return major > 6 or (major == 6 and minor >= 6)

    def is_atleastseven(self):
        """
        Returns True when the Elasticsearch server version >= 7
        """
        return int(self.es_version.split(".")[0]) >= 7

    def resolve_writeback_index(self, writeback_index, doc_type):
        """ In ES6, you cannot have multiple _types per index,
        therefore we use self.writeback_index as the prefix for the actual
        index name, based on doc_type. """
        if not self.is_atleastsix():
            return writeback_index
        elif doc_type == 'silence':
            return writeback_index + '_silence'
        elif doc_type == 'past_elastalert':
            return writeback_index + '_past'
        elif doc_type == 'elastalert_status':
            return writeback_index + '_status'
        elif doc_type == 'elastalert_error':
            return writeback_index + '_error'
        return writeback_index

    @query_params(
        "_source",
        "_source_exclude",
        "_source_excludes",
        "_source_include",
        "_source_includes",
        "allow_no_indices",
        "allow_partial_search_results",
        "analyze_wildcard",
        "analyzer",
        "batched_reduce_size",
        "default_operator",
        "df",
        "docvalue_fields",
        "expand_wildcards",
        "explain",
        "from_",
        "ignore_unavailable",
        "lenient",
        "max_concurrent_shard_requests",
        "pre_filter_shard_size",
        "preference",
        "q",
        "rest_total_hits_as_int",
        "request_cache",
        "routing",
        "scroll",
        "search_type",
        "seq_no_primary_term",
        "size",
        "sort",
        "stats",
        "stored_fields",
        "suggest_field",
        "suggest_mode",
        "suggest_size",
        "suggest_text",
        "terminate_after",
        "timeout",
        "track_scores",
        "track_total_hits",
        "typed_keys",
        "version",
    )
    def deprecated_search(self, index=None, doc_type=None, body=None, params=None):
        """
        Execute a search query and get back search hits that match the query.
        `<https://www.elastic.co/guide/en/elasticsearch/reference/6.0/search-search.html>`_
        :arg index: A list of index names to search, or a string containing a
            comma-separated list of index names to search; use `_all`
            or empty string to perform the operation on all indices
        :arg doc_type: A comma-separated list of document types to search; leave
            empty to perform the operation on all types
        :arg body: The search definition using the Query DSL
        :arg _source: True or false to return the _source field or not, or a
            list of fields to return
        :arg _source_exclude: A list of fields to exclude from the returned
            _source field
        :arg _source_include: A list of fields to extract and return from the
            _source field
        :arg allow_no_indices: Whether to ignore if a wildcard indices
            expression resolves into no concrete indices. (This includes `_all`
            string or when no indices have been specified)
        :arg allow_partial_search_results: Set to false to return an overall
            failure if the request would produce partial results. Defaults to
            True, which will allow partial results in the case of timeouts or
            partial failures
        :arg analyze_wildcard: Specify whether wildcard and prefix queries
            should be analyzed (default: false)
        :arg analyzer: The analyzer to use for the query string
        :arg batched_reduce_size: The number of shard results that should be
            reduced at once on the coordinating node. This value should be used
            as a protection mechanism to reduce the memory overhead per search
            request if the potential number of shards in the request can be
            large., default 512
        :arg default_operator: The default operator for query string query (AND
            or OR), default 'OR', valid choices are: 'AND', 'OR'
        :arg df: The field to use as default where no field prefix is given in
            the query string
        :arg docvalue_fields: A comma-separated list of fields to return as the
            docvalue representation of a field for each hit
        :arg expand_wildcards: Whether to expand wildcard expression to concrete
            indices that are open, closed or both., default 'open', valid
            choices are: 'open', 'closed', 'none', 'all'
        :arg explain: Specify whether to return detailed information about score
            computation as part of a hit
        :arg from\\_: Starting offset (default: 0)
        :arg ignore_unavailable: Whether specified concrete indices should be
            ignored when unavailable (missing or closed)
        :arg lenient: Specify whether format-based query failures (such as
            providing text to a numeric field) should be ignored
        :arg max_concurrent_shard_requests: The number of concurrent shard
            requests this search executes concurrently. This value should be
            used to limit the impact of the search on the cluster in order to
            limit the number of concurrent shard requests, default 'The default
            grows with the number of nodes in the cluster but is at most 256.'
        :arg pre_filter_shard_size: A threshold that enforces a pre-filter
            roundtrip to prefilter search shards based on query rewriting if
            the number of shards the search request expands to exceeds the
            threshold. This filter roundtrip can limit the number of shards
            significantly if for instance a shard can not match any documents
            based on it's rewrite method ie. if date filters are mandatory to
            match but the shard bounds and the query are disjoint., default 128
        :arg preference: Specify the node or shard the operation should be
            performed on (default: random)
        :arg q: Query in the Lucene query string syntax
        :arg rest_total_hits_as_int: This parameter is used to restore the total hits as a number
            in the response. This param is added version 6.x to handle mixed cluster queries where nodes
            are in multiple versions (7.0 and 6.latest)
        :arg request_cache: Specify if request cache should be used for this
            request or not, defaults to index level setting
        :arg routing: A comma-separated list of specific routing values
        :arg scroll: Specify how long a consistent view of the index should be
            maintained for scrolled search
        :arg search_type: Search operation type, valid choices are:
            'query_then_fetch', 'dfs_query_then_fetch'
        :arg size: Number of hits to return (default: 10)
        :arg sort: A comma-separated list of <field>:<direction> pairs
        :arg stats: Specific 'tag' of the request for logging and statistical
            purposes
        :arg stored_fields: A comma-separated list of stored fields to return as
            part of a hit
        :arg suggest_field: Specify which field to use for suggestions
        :arg suggest_mode: Specify suggest mode, default 'missing', valid
            choices are: 'missing', 'popular', 'always'
        :arg suggest_size: How many suggestions to return in response
        :arg suggest_text: The source text for which the suggestions should be
            returned
        :arg terminate_after: The maximum number of documents to collect for
            each shard, upon reaching which the query execution will terminate
            early.
        :arg timeout: Explicit operation timeout
        :arg track_scores: Whether to calculate and return scores even if they
            are not used for sorting
        :arg track_total_hits: Indicate if the number of documents that match
            the query should be tracked
        :arg typed_keys: Specify whether aggregation and suggester names should
            be prefixed by their respective types in the response
        :arg version: Specify whether to return document version as part of a
            hit
        """
        # from is a reserved word so it cannot be used, use from_ instead
        if "from_" in params:
            params["from"] = params.pop("from_")

        if not index:
            index = "_all"
        res = self.transport.perform_request(
            "GET", _make_path(index, doc_type, "_search"), params=params, body=body
        )
        if type(res) == list or type(res) == tuple:
            return res[1]
        return res
