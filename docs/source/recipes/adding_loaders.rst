.. _loaders:

Rules Loaders
========================

RulesLoaders are subclasses of ``RulesLoader``, found in ``elastalert/loaders.py``. They are used to
gather rules for a particular source. Your RulesLoader needs to implement three member functions, and
will look something like this:

.. code-block:: python

    class AwesomeNewRulesLoader(RulesLoader):
        def get_names(self, conf, use_rule=None):
            ...
        def get_hashes(self, conf, use_rule=None):
            ...
        def get_yaml(self, rule):
            ...

You can import loaders by specifying the type as ``module.file.RulesLoaderName``, where module is the name of a
python module, and file is the name of the python file containing a ``RulesLoader`` subclass named ``RulesLoaderName``.

Example
-------

As an example loader, let's retrieve rules from a database rather than from the local file system. First, create a
modules folder for the loader in the ElastAlert 2 directory.

.. code-block:: console

    $ mkdir elastalert_modules
    $ cd elastalert_modules
    $ touch __init__.py

Now, in a file named ``mongo_loader.py``, add

.. code-block:: python

    from pymongo import MongoClient
    from elastalert.loaders import RulesLoader
    import yaml

    class MongoRulesLoader(RulesLoader):
        def __init__(self, conf):
            super(MongoRulesLoader, self).__init__(conf)
            self.client = MongoClient(conf['mongo_url'])
            self.db = self.client[conf['mongo_db']]
            self.cache = {}

        def get_names(self, conf, use_rule=None):
            if use_rule:
                return [use_rule]

            rules = []
            self.cache = {}
            for rule in self.db.rules.find():
                self.cache[rule['name']] = yaml.load(rule['yaml'])
                rules.append(rule['name'])

            return rules

        def get_hashes(self, conf, use_rule=None):
            if use_rule:
                return [use_rule]

            hashes = {}
            self.cache = {}
            for rule in self.db.rules.find():
                self.cache[rule['name']] = rule['yaml']
                hashes[rule['name']] = rule['hash']

            return hashes

        def get_yaml(self, rule):
            if rule in self.cache:
                return self.cache[rule]

            self.cache[rule] = yaml.load(self.db.rules.find_one({'name': rule})['yaml'])
            return self.cache[rule]

Finally, you need to specify in your ElastAlert 2 configuration file that MongoRulesLoader should be used instead of the
default FileRulesLoader, so in your ``elastalert.conf`` file::

    rules_loader: "elastalert_modules.mongo_loader.MongoRulesLoader"

