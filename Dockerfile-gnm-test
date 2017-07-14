FROM alpine:latest

RUN apk update && apk upgrade && \
   apk add tzdata python py-yaml curl wget bash python-dev git && \
   apk add build-base && \ 
   # Install setuptools
   curl https://bootstrap.pypa.io/ez_setup.py -o - | python && \
   # install supervisord
   easy_install supervisor && \
   # Checkout Yelp/elastalert
   mkdir -p /usr/src && \
   cd /usr/src/ && \
   git clone https://github.com/Yelp/elastalert.git && \
   # Build elastalert
   cd /usr/src/elastalert/ && \
   python setup.py install && \
   # Setup config directory
   sed -i 's/example_rules/rules/g' config.yaml.example && \
   mkdir -p /opt/elastalert/rules && \
   mv config.yaml.example /opt/elastalert/config.yaml && \
   mv supervisord.conf.example /opt/elastalert/supervisord.conf && \
   sed -i -e 's/nodaemon=false/nodaemon=true/' /opt/elastalert/supervisord.conf && \
   ln -s $(find /usr/lib/python* -name elastalert.py) /opt/elastalert/elastalert.py && \
   # Include example_rules folder
   mkdir -p /opt/elastalert/example_rules && \
   cp example_rules/* /opt/elastalert/example_rules/ && \
   # Remove files to save space
   cd / && \
   rm -rf /usr/src/elastalert && \
   apk del python-dev git && \
   rm -rf /var/cache/apk/* && \
   cp /usr/share/zoneinfo/America/New_York /etc/localtime && \
   echo "America/New_York" >  /etc/timezone && \
   echo "EST5EDT" >  /etc/TZ && \ 
   apk del build-base

WORKDIR /opt/elastalert

ONBUILD COPY config.yaml /opt/elastalert/config.yaml
ONBUILD COPY rules/* /opt/elastalert/rules/
VOLUME ["/opt/elastalert"]
VOLUME ["/var/log"]

CMD ["supervisord","-c","/opt/elastalert/supervisord.conf"]

COPY Dockerfile /Dockerfile
