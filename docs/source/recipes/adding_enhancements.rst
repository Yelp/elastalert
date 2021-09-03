.. _enhancements:

Enhancements
============

Enhancements are modules which let you modify a match before an alert is sent. They should subclass ``BaseEnhancement``, found in ``elastalert/enhancements.py``.
They can be added to rules using the ``match_enhancements`` option::

    match_enhancements:
    - module.file.MyEnhancement

where module is the name of a Python module, or folder containing ``__init__.py``,
and file is the name of the Python file containing a ``BaseEnhancement`` subclass named ``MyEnhancement``.

A special exception class ```DropMatchException``` can be used in enhancements to drop matches if custom conditions are met. For example:

.. code-block:: python

    class MyEnhancement(BaseEnhancement):
        def process(self, match):
            # Drops a match if "field_1" == "field_2"
            if match['field_1'] == match['field_2']:
                raise DropMatchException()

Example
-------

As an example enhancement, let's add a link to a whois website. The match must contain a field named domain and it will 
add an entry named domain_whois_link. First, create a modules folder for the enhancement in the ElastAlert 2 directory.

.. code-block:: console

    $ mkdir elastalert_modules
    $ cd elastalert_modules
    $ touch __init__.py

Now, in a file named ``my_enhancements.py``, add


.. code-block:: python

    from elastalert.enhancements import BaseEnhancement

    class MyEnhancement(BaseEnhancement):

        # The enhancement is run against every match
        # The match is passed to the process function where it can be modified in any way
        # ElastAlert 2 will do this for each enhancement linked to a rule
        def process(self, match):
            if 'domain' in match:
                url = "http://who.is/whois/%s" % (match['domain'])
                match['domain_whois_link'] = url

Enhancements will not automatically be run. Inside the rule configuration file, you need to point it to the enhancement(s) that it should run
by setting the ``match_enhancements`` option::

    match_enhancements:
    - "elastalert_modules.my_enhancements.MyEnhancement"

