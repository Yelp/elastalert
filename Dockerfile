# UNDER DEVELOPMENT

# FROM python:3-slim as build

# ENV ELASTALERT_HOME /opt/elastalert
# ADD . /opt/elastalert/

# WORKDIR /opt

# RUN apk add --update --no-cache jq curl gcc openssl-dev libffi-dev openssl ca-certificates musl-dev python-dev
# RUN pip install "setuptools==36.2.7" "elasticsearch==6.3.1"

# WORKDIR "${ELASTALERT_HOME}"

# RUN pip install -r requirements.txt
# RUN  python setup.py install

# FROM gcr.io/distroless/python3:debug as runtime

# COPY --from=build /opt/elastalert /opt/elastalert
# COPY --from=build /usr/local/lib/python3 /usr/local/lib/python3
# COPY --from=build /usr/local/bin/elastalert* /usr/local/bin/
# COPY --from=build /usr/local/lib/libpython2.7.so.1.0 /usr/local/lib/
# COPY --from=build /usr/lib/libpython2.7.so.1.0 /usr/lib/
# COPY --from=build /lib/libc.musl-x86_64.so.1 /lib/

# #COPY  --from=build /data/elastalert /data/elastalert

# ENV PYTHONPATH=/usr/local/lib/python2.7/site-packages
# ENV PATH=/usr/local/lib:/usr/lib:$PATH

# WORKDIR /opt/elastalert

# CMD ["/usr/local/bin/elastalert-create-index","--config","/data/elastalert/config.yaml", "--verbose"]
# CMD ["/usr/local/bin/elastalert","--config","/data/elastalert/config.yaml", "--verbose"]
