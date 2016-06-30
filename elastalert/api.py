import argparse
from flask import Flask, jsonify, request
import sys
from config import get_file_paths, load_configuration
from staticconf.loader import yaml_loader
import yaml
import re
import string
import os
from util import EAException
from base64 import b64encode, b64decode
from test_rule import MockElastAlerter
import StringIO
from flask.ext.cors import CORS

""" A REST API webserver that allows for interaction with ElastAlert from
an API. """

app = Flask(__name__)
CORS(app)

# Parse the arguments
parser = argparse.ArgumentParser()
parser.add_argument('--config', action='store', dest='config', default="config.yaml", help='Global config file (default: config.yaml)')
parser.add_argument('--rule', dest='rule', help='Run only a specific rule (by filename, must still be in rules folder)')
args = parser.parse_args(sys.argv[1:])
conf = {}

def load_rules():
    global conf
    conf = yaml_loader(args.config)
    conf.setdefault('max_query_size', 100000)
    conf.setdefault('disable_rules_on_error', True)
    # Load each rule configuration file
    rules = {} # empty rules dict
    rule_files = get_file_paths(conf)
    for rule_file in rule_files:
        try:
            rule = yaml_loader(rule_file)
            rule['rule_file'] = rule_file
        except yaml.scanner.ScannerError as e:
            raise EAException('Could not parse file %s: %s' % (filename, e))
        except EAException as e:
            raise EAException('Error loading file %s: %s' % (rule_file, e))

        rule['rule_id'] = b64encode(rule['name'])
        rules[rule['rule_id']] = rule
    return rules

def slugify(s):
    """ Convert String to a filename slug """
    valid_chars = "-_.()%s%s" % (string.ascii_letters, string.digits)
    return ''.join(c for c in s if c in valid_chars)

def save_rule(filepath, rule):
    if not os.path.exists(os.path.dirname(filepath)):
        os.makedirs(os.path.dirname(filepath))
    with open(filepath, 'w') as outfile:
        outfile.write(yaml.safe_dump(rule, default_flow_style=False))

def test_rule(filepath, days=1):
    test_instance = MockElastAlerter()

    # I have to do some hackery to mimic an argparser object
    def args():
        file = None
        schema_only = None
        days = None
        save = None
        count = None

    args.file = filepath
    args.schema_only = False
    args.days = days
    args.save = False
    args.count = False

    # Redirect STDOUT to get output from rule test
    testOutputHandler = StringIO.StringIO()
    sys.stdout = testOutputHandler
    sys.stderr = testOutputHandler

    # Run rule test
    test_instance.test_file(args)

    # Assign output of method to string
    ruleTestOutput = testOutputHandler.getvalue()

    # Restore sys.stdout and sys.stderr
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__

    return ruleTestOutput

@app.route("/elastalert/api", methods=['GET'])
def index():
    return jsonify({ "name": "ElastAlert Rest API" })

@app.route("/elastalert/api/rules/<rule_id>", methods=['GET', 'DELETE'])
def rule(rule_id):
    if request.method == 'DELETE':
        rules = load_rules()
        if rule_id in rules:
            os.remove(rules[rule_id]["rule_file"])
            return jsonify({"response": "Rule Deleted"})
    else:
        # GET
        rules = load_rules()
        return jsonify(rules[rule_id])

@app.route("/elastalert/api/rules/test", methods=['POST'])
def test():
    rule = request.get_json()

    filepath = "%s/%s.yaml" % ("temp_test_rules",
                               slugify(rule["name"]))

    save_rule(filepath, rule)

    result = test_rule(filepath)

    return jsonify({"test_results": result})

@app.route("/elastalert/api/rules", methods=['GET', 'POST'])
def rules():
    if request.method == 'POST':
        # create a rule
        new_rule = request.get_json()
        load_rules()

        # Verify rule has required fields
        required_fields = ["es_host", "es_port", "index", "name", "type",
                           "alert"]
        if all(field in new_rule for field in required_fields):
            filepath = "%s/%s.yaml" % (conf['rules_folder'],
                                       slugify(new_rule["name"]))
            save_rule(filepath, new_rule)
            return jsonify({"response": "Rule Created"})
        else:
            return jsonify({"response": "Rule Invalid"})
    else:
        # GET
        return jsonify(load_rules())

def main():
    app.run(debug=True, ssl_context=('/Users/calebc/Projects/elastalert/certificates/server.crt', '/Users/calebc/Projects/elastalert/certificates/server.key'))

if __name__ == '__main__':
    app.run(debug=True)
