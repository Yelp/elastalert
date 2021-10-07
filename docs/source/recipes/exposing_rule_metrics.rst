.. _exposingrulemetrics:

Exposing Rule Metrics
=====================

Configuration
-------------
Running ElastAlert with ``--prometheus_port`` configuration flag will expose ElastAlert 2 Prometheus metrics on the specified port. Prometheus metrics are disabled by default.

To expose ElastAlert rule metrics on port ``9979`` run the following command:

.. code-block:: console

    $ elastalert --config config.yaml --prometheus_port 9979 

Rule Metrics
------------

The metrics being exposed are related to the `ElastAlert metadata indices <https://elastalert2.readthedocs.io/en/latest/elastalert_status.html>`_. The exposed metrics are in the `Prometheus text-based format <https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format>`_. Metrics are of the metric type `counter <https://prometheus.io/docs/concepts/metric_types/#counter>`_ or `gauge <https://prometheus.io/docs/concepts/metric_types/#gauge>`_ and follow the `Prometheus metric naming <https://prometheus.io/docs/practices/naming/>`_. 

In the standard metric definition, the metric names are structured as follows:

.. code-block:: console

     elastalert_{metric}_{unit}

Where:

- ``{metric}`` is a unique name of the metric. For example, ``hits``.
- ``{unit}`` is the unit of measurement of the metric value. For example, ``total`` is a counter type metric and ``created`` is a gauge type metric.

All metrics except ``elastalert_errors_{unit}`` have values that apply to a particular rule name. In the exported metrics, these can be identified using the ``rule_name`` `Prometheus label <https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels>`_.

Find below all available metrics:

+---------------------------------------+-----------------+---------------------------+---------------+
|    METRIC                             |  Type           |  Description              |  Label        |
+=======================================+=================+===========================+===============+
| ``elastalert_scrapes_{unit}``         | Counter, Gauge  | Number of scrapes         | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_hits_{unit}``            | Counter, Gauge  | Number of hits            | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_matches_{unit}``         | Counter, Gauge  | Number of matches         | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_time_taken_{unit}``      | Counter, Gauge  | Time taken in seconds     | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_alerts_sent_{unir}``     | Counter, Gauge  | Number of alerts sent     | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_alerts_not_sent_{unit}`` | Counter, Gauge  | Number of alerts not sent | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_alerts_silenced_{unit}`` | Counter, Gauge  | Number of silenced alerts | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_errors_{unit}``          | Counter, Gauge  | Number of errors          |               |
+---------------------------------------+-----------------+---------------------------+---------------+




