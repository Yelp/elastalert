# Elastalert Docker Image

Docker image with Elastalert on Alpine Linux.

Assumes the use of port 9200 when communicating with Elasticsearch.
In order for the time of the container to be synchronized (ntpd), it must be run with the SYS_TIME capability.
In addition you may want to add the SYS_NICE capability, in order for ntpd to be able to modify its priority.

If Elasticsearch requires authentication, then the two environment variables listed below must contain user and password.
In addition, if you mount the Elastalert configuration file you must add login credentials, like in this example:
```
es_username: elastic
es_password: changeme
```

# Volumes

- /opt/logs       - Elastalert and Supervisord logs will be written to this directory.
- /opt/config     - Elastalert (elastalert_config.yaml) and Supervisord (elastalert_supervisord.conf) configuration files.
- /opt/rules      - Contains Elastalert rules.


# Environment

- SET_CONTAINER_TIMEZONE - Set to "True" (without quotes) to set the timezone when starting a container. Default is `False`.
- CONTAINER_TIMEZONE - Timezone to use in container. Default is `Europe/Stockholm`.
- ELASTICSEARCH_HOST - IP or hostname for your Elasticsearch host. Defaults to `elasticsearchhost`.
- ELASTICSEARCH_PORT - Port for your Elasticsearch host. Defaults to `9200`.
- ELASTICSEARCH_USER - Name of user to log into Ealsticsearch with. Leave undefined for no authentication.
- ELASTICSEARCH_PASSWORD - Password to log into Elasticsearch with. Leave undefined for no authentication.
- ELASTICSEARCH_TLS - Use HTTPS when connecting to Elasticsearch (True/False). Default is `False`.
- ELASTICSEARCH_TLS_VERIFY - Verify server (Elasticsearch) certificate (True/False). Default is `False`.
- ELASTALERT_INDEX - Name of Elastalert writeback index in Elasticseach. Defaults to `elastalert_status`.
