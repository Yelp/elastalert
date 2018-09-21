FROM alpine:3.8 as build

ENV ELASTALERT_HOME /opt/elastalert
WORKDIR "${ELASTALERT_HOME}"

RUN apk add --update --no-cache ca-certificates openssl-dev openssl python2-dev python2 py2-pip py2-yaml libffi-dev gcc musl-dev libmagic

COPY . ./

RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    python setup.py install

RUN elastalert-test-rule --help && elastalert --help


# Multistage build, copy build results from first intermediate image
FROM alpine:3.8

ENV ELASTALERT_HOME /opt/elastalert
WORKDIR "${ELASTALERT_HOME}"

RUN apk add --update --no-cache python2 libmagic
COPY --from=build /usr/lib/python2.7/site-packages /usr/lib/python2.7/site-packages
COPY --from=build /opt/elastalert /opt/elastalert
COPY --from=build /usr/bin/elastalert* /usr/bin/

ENTRYPOINT ["/usr/bin/elastalert"]
