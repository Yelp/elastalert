FROM python:2.7

WORKDIR /usr/src/app/

COPY ./requirements.txt /usr/src/app/
RUN pip install --no-cache -r requirements.txt

COPY ./requirements-dev.txt /usr/src/app/
RUN pip install --no-cache -r requirements-dev.txt

RUN \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y install curl \
  && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

COPY . /usr/src/app/

ENTRYPOINT [ "python", "elastalert/elastalert.py" ]
CMD [ "--config", "config.yaml" ]
