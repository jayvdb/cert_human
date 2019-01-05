CLI Reference
======================

.. automodule:: cert_human_cli
    :members:

Help
----

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py --help
    usage: cert_human_cli.py [-h] [--port PORT] [--method {requests,socket}]
                             [--chain] [--print_mode {info,key,extensions,all}]
                             [--write WRITE] [--overwrite] [--verify VERIFY]
                             HOST

    Command line interface to request a URL and get the server cert or cert chain.

    positional arguments:
      HOST                  Host to get cert or cert chain from

    optional arguments:
      -h, --help            show this help message and exit
      --port PORT           Port on host to connect to (default: 443)
      --method {requests,socket}
                            Use requests.get a SSL socket to get cert or cert
                            chain. (default: requests)
      --chain               Print/write the cert chain instead of the cert.
                            (default: False)
      --print_mode {info,key,extensions,all}
                            When no --write specified, print this type of
                            information for the cert. (default: info)
      --write WRITE         File to write cert/cert chain to (default: )
      --overwrite           When writing to --write and file exists, overwrite.
                            (default: False)
      --verify VERIFY       PEM file to verify host, empty will disable verify,
                            for --method requests. (default: )
