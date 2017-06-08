deadsnakes:
  pkgrepo.managed:
    - ppa: fkrull/deadsnakes
    - require_in:
      - pkg: python2.6
      - pkg: python2.6-dev

python2.6:
  pkg.installed

python2.6-dev:
  pkg.installed

python-pip:
  pkg.installed

python-dev:
  pkg.installed
