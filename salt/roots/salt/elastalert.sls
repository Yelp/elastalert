elastalert-supervisor:
  file.managed:
    - name: /etc/supervisor/conf.d/elastalert.conf
    - source: salt://supervisor/supervisor.conf
    - template: jinja
    - require:
      - sls: supervisor
  supervisord.running:
    - name: elastalert
    - update: True
    - restart: True
    - require:
      - sls: supervisor
      - file: elastalert-config
      - cmd: elastalert-install
      - cmd: elastalert-create-index

elastalert-requirements:
  pip.installed:
    - cwd: /vagrant
    - requirements: requirements-dev.txt
    - require:
      - sls: python

elastalert-config:
  file.managed:
    - name: /etc/elastalert/config.yaml
    - source: salt://elastalert/config.yaml
    - template: jinja
    - makedirs: True

elastalert-rules:
  file.recurse:
    - name: /etc/elastalert/rules
    - source: salt://elastalert/rules
    - makedirs: True

elastalert-create-index:
  cmd.run:
    - name: elastalert-create-index --no-auth --no-ssl --index=elastalert_status --old-index=''
    - cwd: /etc/elastalert
    - require:
      - file: elastalert-config

elastalert-install:
  cmd.run:
    - name: python setup.py install
    - cwd: /vagrant
    - require:
      - pip: elastalert-requirements
