FROM python:3.9-alpine as build

ENV ELASTALERT_HOME /opt/elastalert
ADD . /opt/elastalert/

WORKDIR /opt

RUN apk add --update --no-cache jq curl gcc openssl-dev libffi-dev ca-certificates musl-dev
RUN pip install "setuptools==65.5.0" "elasticsearch==6.3.1"

WORKDIR "${ELASTALERT_HOME}"

RUN pip install -r requirements.txt
RUN python setup.py install

RUN pip show elastalert2

RUN echo "coming here..."
RUN ls /usr/local/lib/
RUN ls /usr/lib/
RUN ls /lib/

FROM gcr.io/distroless/python3:debug as runtime

COPY --from=build /opt/elastalert /opt/elastalert
COPY --from=build /usr/local/bin/elastalert* /usr/local/bin/

COPY --from=build /opt/elastalert /opt/elastalert 
COPY --from=build /usr/local/lib/python3.9 /usr/local/lib/python3.9
COPY --from=build /usr/local/bin/elastalert* /usr/local/bin/
COPY --from=build /usr/local/lib/libpython3.9.so.1.0 /usr/local/lib/
COPY --from=build /lib/libc.musl-x86_64.so.1 /lib/

#COPY  --from=build /data/elastalert /data/elastalert

ENV PYTHONPATH=/usr/local/lib/python3.9/site-packages
ENV PATH=/usr/local/lib:/usr/lib:$PATH

RUN ls /usr/local/bin/
RUN python --version

WORKDIR /opt/elastalert

ENTRYPOINT ["python","-m","elastalert.create_index","--config","/data/elastalert/config.yaml", "--verbose"]
ENTRYPOINT ["python","-m","elastalert.elastalert","--config","/data/elastalert/config.yaml", "--verbose"]
