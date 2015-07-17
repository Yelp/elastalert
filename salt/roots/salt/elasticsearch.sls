openjdk-7-jre-headless:
  pkg.installed

elasticsearch:
    pkg.installed:
        - sources:
            - elasticsearch: https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.6.0.deb
        - require:
          - pkg: openjdk-7-jre-headless
    service.running:
        - name: elasticsearch
        - running: True
        - enable: True
        - require:
            - pkg: elasticsearch
