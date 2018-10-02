FROM ubuntu:latest

RUN apt-get update && apt-get upgrade -y
RUN apt-get -y install build-essential python-setuptools python2.7 python2.7-dev libssl-dev git tox python-pip

WORKDIR /home/elastalert

ADD requirements*.txt ./
RUN pip install -r requirements-dev.txt
