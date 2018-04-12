FROM alpine

RUN apk update && \
    apk --no-cache add ca-certificates openssl python2 py2-pip py2-yaml tzdata

ENV ELASTALERT_HOME /opt/elastalert/

WORKDIR /opt

ADD setup.py requirements.txt elastalert "${ELASTALERT_HOME}"

WORKDIR "${ELASTALERT_HOME}"

RUN apk --no-cache add --virtual build-dependencies python2-dev musl-dev gcc openssl-dev libffi-dev && \
    pip install -r requirements.txt && \
    python setup.py install && \
    apk del build-dependencies

CMD [ "python", "-m", "elastalert", "--config", "/opt/config/elastalert_config.yaml", "--verbose" ]
