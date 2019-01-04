# -*- coding: utf-8 -*-
"""Test suite for cert_human."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import cert_human
import requests
import urllib3


class TestCertHuman:

    def test_entry_points(self):
        cert_human.CertStore
        cert_human.CertChainStore
        assert issubclass(cert_human.HTTPSConnectionWithCertCls, urllib3.connection.HTTPSConnection)
        assert issubclass(cert_human.ResponseWithCertCls, urllib3.response.HTTPResponse)

    def test_enable_urllib3_patch(self, httpbin_secure, httpbin_ca_bundle):
        cert_human.enable_urllib3_patch()
        r = requests.get(httpbin_secure(), verify=httpbin_ca_bundle)
        assert getattr(r.raw, "peer_cert", None)
        assert getattr(r.raw, "peer_cert_chain", None)
        assert getattr(r.raw, "peer_cert_dict", None)
        cert_human.disable_urllib3_patch()

    def test_disable_urllib3_patch(self, httpbin_secure, httpbin_ca_bundle):
        cert_human.disable_urllib3_patch()
        r = requests.get(httpbin_secure(), verify=httpbin_ca_bundle)
        assert not getattr(r.raw, "peer_cert", None)
        assert not getattr(r.raw, "peer_cert_chain", None)
        assert not getattr(r.raw, "peer_cert_dict", None)

    def test_urllib3_patch(self, httpbin_secure, httpbin_ca_bundle):
        with cert_human.urllib3_patch():
            r = requests.get(httpbin_secure(), verify=httpbin_ca_bundle)
            assert getattr(r.raw, "peer_cert", None)
            assert getattr(r.raw, "peer_cert_chain", None)
            assert getattr(r.raw, "peer_cert_dict", None)
        r = requests.get(httpbin_secure(), verify=httpbin_ca_bundle)
        assert not getattr(r.raw, "peer_cert", None)
        assert not getattr(r.raw, "peer_cert_chain", None)
        assert not getattr(r.raw, "peer_cert_dict", None)

    def test_using_urllib3_patch(self):
        with cert_human.urllib3_patch():
            assert cert_human.using_urllib3_patch()
        assert not cert_human.using_urllib3_patch()

    def test_build_url_only_host(self):
        url = cert_human.build_url(host="cyborg")
        assert url == "https://cyborg:443"

    def test_build_url_host_port(self):
        url = cert_human.build_url(host="cyborg", port=445)
        assert url == "https://cyborg:445"

    def test_build_url_port_in_host(self):
        url = cert_human.build_url(host="cyborg:445")
        assert url == "https://cyborg:445"

    def test_build_url_scheme_in_host(self):
        url = cert_human.build_url(host="http://cyborg")
        assert url == "http://cyborg:443"

    def test_build_url_port_scheme_in_host(self):
        url = cert_human.build_url(host="http://cyborg:445")
        assert url == "http://cyborg:445"

    def test_test_cert_invalid(self, httpbin_secure):
        valid, exc = cert_human.test_cert(host=httpbin_secure())
        assert not valid
        assert isinstance(exc, requests.exceptions.SSLError)

    def test_test_cert_valid(self, httpbin_secure, httpbin_ca_bundle):
        valid, exc = cert_human.test_cert(host=httpbin_secure(), path=httpbin_ca_bundle)
        assert valid
        assert exc is None


'''
get_response
ssl_socket
CertStore
CertChainStore
utf8
indent
clsname
jdump
hexify
space_out
wrap_it
write_file
find_certs
pem_to_x509
pems_to_x509
x509_to_pem
x509_to_der
x509_to_asn1
der_to_asn1
'''
