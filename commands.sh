#!/bin/bash
echo "creating elastalert indices"
python -m elastalert.create_index --config /data/elastalert/config.yaml
echo "Starting elastalert"
python -m elastalert.elastalert --config /data/elastalert/config.yaml --verbose
