import os
import yaml


def read_yaml(path):
    with open(path) as f:
        yamlContent = os.path.expandvars(f.read())
        return yaml.load(yamlContent, Loader=yaml.FullLoader)
