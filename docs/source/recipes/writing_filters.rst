.. _writingfilters:

Writing Filters For Rules
=========================

This document describes how to create a filter section for your rule config file.

The filters used in rules are part of the Elasticsearch query DSL, further documentation for which can be found at
https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
This document contains a small subset of particularly useful filters.

The filter section is passed to Elasticsearch exactly as follows::

    filter:
      and:
        filters:
          - [filters from rule.yaml]

Every result that matches these filters will be passed to the rule for processing.

Common Filter Types:
--------------------

query_string
************

The query_string type follows the Lucene query format and can be used for partial or full matches to multiple fields.
See http://lucene.apache.org/core/2_9_4/queryparsersyntax.html for more information::

    filter:
    - query:
        query_string:
          query: "username: bob"
    - query:
        query_string:
          query: "_type: login_logs"
    - query:
        query_string:
          query: "field: value OR otherfield: othervalue"
    - query:
        query_string:
           query: "this: that AND these: those"

term
****

The term type allows for exact field matches::

    filter:
    - term:
        name_field: "bob"
    - term:
        _type: "login_logs"

Note that a term query may not behave as expected if a field is analyzed. By default, many string fields will be tokenized by whitespace, and a term query for "foo bar" may not match
a field that appears to have the value "foo bar", unless it is not analyzed. Conversely, a term query for "foo" will match analyzed strings "foo bar" and "foo baz". For full text
matching on analyzed fields, use query_string. See https://www.elastic.co/guide/en/elasticsearch/guide/current/term-vs-full-text.html

`terms <https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-terms-query.html>`_
*****************************************************************************************************



Terms allows for easy combination of multiple term filters::

    filter:
    - terms:
        field: ["value1", "value2"] # value1 OR value2

You can also match on multiple fields (All terms must match at least one of the given values)::

    - terms:
        fieldX: ["value1", "value2"]
    - terms:
        fieldY: ["something", "something_else"]
    - terms:
        fieldZ: ["foo", "bar", "baz"]

wildcard
********

For wildcard matches::

    filter:
    - query:
        wildcard:
          field: "foo*bar"

range
*****

For ranges on fields::

    filter:
    - range:
        status_code:
          from: 500
          to: 599

Negation, and, or
*****************

Below is a more complex example for Elasticsearch 7.x, provided by a `community user. <https://github.com/jertel/elastalert2/discussions/330>`_::

    filter:
    - term:
        action: order
    - terms:
        dining:
            - pickup
            - delivery
    - bool:
        #exclude common/expected orders
        must_not:
            #Alice usually gets a pizza
            - bool:
                must: [ {term: {uid: alice}}, {term: {menu_item: pizza}} ]
            #Bob loves his hoagies 
            - bool:
                must: [ {term: {uid: bob}}, {term: {menu_item: sandwich}} ]
            #Charlie has a few favorites
            - bool:
                must:
                   - term:
                       uid: charlie
                   - match:
                       menu_item: "burrito pasta salad pizza"
