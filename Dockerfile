FROM alpine

LABEL description="ElastAlert suitable for Kubernetes and Helm"
LABEL maintainer="Jason Ertel (jertel at codesim.com)"

ARG ELASTALERT_VERSION=0.1.39

RUN apk --update upgrade && \
    apk add ca-certificates gcc libffi-dev musl-dev python2 python2-dev py2-pip py2-yaml openssl openssl-dev tzdata file-dev && \
    rm -rf /var/cache/apk/*

RUN wget https://github.com/Yelp/elastalert/archive/v${ELASTALERT_VERSION}.zip -O /tmp/elastalert.zip && \
    mkdir /opt && \
    unzip /tmp/elastalert.zip -d /opt && \
    rm -f /tmp/elastalert.zip && \
    mv /opt/elastalert-${ELASTALERT_VERSION} /opt/elastalert && \
    cd /opt/elastalert && \
    pip install elasticsearch==6.3.1 && \
    python setup.py install && \
    pip install -e . && \
    apk del gcc libffi-dev musl-dev openssl-dev python2-dev

COPY ./elastalert/elastalert.py /opt/elastalert/elastalert
COPY ./elastalert/ruletypes.py /opt/elastalert/elastalert

RUN mkdir -p /opt/elastalert/config && \
    mkdir -p /opt/elastalert/rules && \
    echo "#!/bin/sh" >> /opt/elastalert/run.sh && \
    echo "elastalert-create-index --config /opt/config/elastalert_config.yaml" >> /opt/elastalert/run.sh && \
    echo "exec elastalert --config /opt/config/elastalert_config.yaml \"\$@\"" >> /opt/elastalert/run.sh && \
    chmod +x /opt/elastalert/run.sh

VOLUME [ "/opt/config", "/opt/rules" ]
WORKDIR /opt/elastalert
ENTRYPOINT ["/opt/elastalert/run.sh"]
