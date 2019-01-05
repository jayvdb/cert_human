|Maintenance yes|
|MIT license|
|Open Source? Yes!|
|made-with-python|
|code-black|
|vulnerabilities|

#######################################
Cert Human: SSL Certificates for Humans
#######################################

**************************
Description
**************************

Somebody said something about over-engineering. So I obviously had to chime in.

No, but seriously, I was in the midst of rewriting `another project of mine <https://github.com/tanium/pytan>`_, and I wanted to incorporate a method to get an SSL certificate from a server, show the user the same kind of information as you'd see in a browser, prompt them for validity, then write it to disk for use in further requests using :obj:`requests` to a server.

I was unable to find any great / easy ways that incorporated all of these concepts into one neat thing. So I made a thing.

Originally this was based off of the lovely over-engineered solution in `get-ca-py <https://github.com/neozenith/get-ca-py>`_ by `Josh Peak <https://github.com/neozenith>`_.

I wound up wanting a more offically supported way of patching urllib3 to have access to the certificate attributes in the raw attribute of a :obj:`requests.Response` object. So I wrote :ref:`Replacement Connect and Response subclasses <WithCert Classes>` for :obj:`urllib3.HTTPSConnectionPool`, and a :ref:`patcher, unpatcher, and context manager <WithCert Functions>` to enable/disable the new classes.

I also wanted some generalized utility functions to get the certificates, so I wrote some :ref:`get certificate functions <Get Cert Functions>`.

I then wanted an easier, more *human* way of accessing all of the information in the certificates. And that wound up turning into a whole thing. So :ref:`CertStore and CertChainStore classes <Store Classes>` were born.


**************************
Python Versions Supported
**************************

I only focused on writing and testing for the latest versions of 2.7 and 3.7. It might work on other versions, have fun.

**************************
Installation
**************************

Install into your system wide site-packages:

.. code-block:: console

    $ pip install cert_human

Or install into your pipenv:

.. code-block:: console

    $ pipenv install cert_human

**************************
Get the Source Code
**************************

Cert Human is actively developed on GitHub, where the code is
`always available <https://github.com/lifehackjim/cert_human>`_.

You can clone the public repository:

.. code-block:: console

    $ git clone git://github.com/lifehackjim/cert_human.git

Once you have a copy of the source, you can embed it in your own Python
package, or install it into your site-packages easily::

    $ cd requests
    $ pip install .


**************************
TODO items
**************************

* Figure out test suite for cli

.. |MIT license| image:: https://img.shields.io/badge/License-MIT-blue.svg
   :target: https://lbesson.mit-license.org/

.. |Open Source? Yes!| image:: https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github
   :target: https://github.com/lifehackjim/cert_human

.. |Maintenance yes| image:: https://img.shields.io/badge/Maintained%3F-yes-green.svg
   :target: https://github.com/lifehackjim/cert_human/graphs/commit-activity

.. |made-with-python| image:: https://img.shields.io/badge/Made%20with-Python-1f425f.svg
   :target: https://www.python.org/

.. |code-black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/ambv/black

.. |vulnerabilities| image:: https://snyk.io/test/github/lifehackjim/cert_human/badge.svg?targetFile=requirements.txt
   :target: https://snyk.io/test/github/lifehackjim/cert_human?targetFile=requirements.txt

###################
Table of Contents
###################

.. toctree::
   :maxdepth: 4
   :numbered:

   cli/cli.rst
   api/api.rst

###################
Indices and tables
###################

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
