# -*- coding: utf-8 -*-
"""Conf for py.test."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pytest
import pytest_httpbin.certs
import pytest_httpbin.serve
from requests.compat import urljoin

try:
    import pathlib
except ImportError:
    import pathlib2 as pathlib

THIS_DIR = pathlib.Path(__file__).absolute().parent

# borrowed judiciously from requests.


def prepare_url(value):
    httpbin_url = value.url.rstrip('/') + '/'

    def inner(*suffix):
        return urljoin(httpbin_url, '/'.join(suffix))

    return inner


@pytest.fixture
def httpbin(httpbin):
    return prepare_url(httpbin)


@pytest.fixture
def httpbin_secure(httpbin_secure):
    return prepare_url(httpbin_secure)


@pytest.fixture
def cert_dir():
    return THIS_DIR / "certs"


@pytest.fixture
def example_cert(cert_dir):
    return cert_dir / "cert.pem"


@pytest.fixture
def other_cert(cert_dir):
    return cert_dir / "othercert.pem"


@pytest.fixture
def ec_cert(cert_dir):
    return cert_dir / "eccert.pem"


@pytest.fixture
def httpbin_builtin_cert_dir():
    return pathlib.Path(pytest_httpbin.serve.CERT_DIR).absolute()


@pytest.fixture
def httpbin_builtin_cert(httpbin_builtin_cert_dir):
    return httpbin_builtin_cert_dir / "cert.pem"


@pytest.fixture
def httpbin_cert(monkeypatch, example_cert, cert_dir):
    # patch the pytest_httpbin.serve.CERT_DIR to use our own cert_dir
    # pytest_httpbin.serve.SecureWSGIServer offers certs using key.pem and cert.pem from CERT_DIR
    monkeypatch.setattr(pytest_httpbin.serve, "CERT_DIR", format(cert_dir))
    # return the cert that will be offered by pytest_httpbin.serve.SecureWSGIServer
    return format(example_cert)
