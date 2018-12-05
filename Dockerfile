FROM alpine:3.8

ENV ELASTALERT_HOME /opt/elastalert

RUN apk add --update --no-cache ca-certificates openssl-dev openssl python2-dev python2 py2-pip py2-yaml libffi-dev gcc musl-dev libmagic

RUN mkdir /source
WORKDIR /source
USER root

COPY . /source

RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    python setup.py install

ENTRYPOINT ["/usr/bin/elastalert"]
