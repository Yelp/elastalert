FROM python:alpine as builder

LABEL description="Elastalert 2 suitable for Kubernetes and Helm"
LABEL maintainer="Jason Ertel (jertel at codesim.com)"

RUN apk --update upgrade && \
    apk add git && \
    rm -rf /var/cache/apk/*

RUN mkdir -p /opt/elastalert && \
    git clone https://github.com/jertel/elastalert2 /tmp/elastalert && \
    cd /tmp/elastalert && \
    pip install setuptools wheel && \
    python setup.py sdist bdist_wheel

FROM python:alpine

COPY --from=builder /tmp/elastalert/dist/*.tar.gz /tmp/

RUN apk --update upgrade && \
    apk add gcc libffi-dev musl-dev python3-dev openssl-dev tzdata libmagic cargo && \
	pip install /tmp/*.tar.gz && \
    apk del gcc libffi-dev musl-dev python3-dev openssl-dev cargo && \
    rm -rf /var/cache/apk/*

RUN mkdir -p /opt/elastalert && \
	echo "#!/bin/sh" >> /opt/elastalert/run.sh && \
    echo "set -e" >> /opt/elastalert/run.sh && \
    echo "elastalert-create-index --config /opt/config/elastalert_config.yaml" >> /opt/elastalert/run.sh && \
    echo "elastalert --config /opt/config/elastalert_config.yaml \"\$@\"" >> /opt/elastalert/run.sh && \
    chmod +x /opt/elastalert/run.sh

ENV TZ "UTC"

WORKDIR /opt/elastalert
ENTRYPOINT ["/opt/elastalert/run.sh"]
