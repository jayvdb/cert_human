# -*- coding: utf-8 -*-
"""Test suite for cert_human."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import cert_human
import json
import datetime
import requests
import urllib3
import pytest
import stat
import tempfile
import OpenSSL
import six
import asn1crypto


class TestUrllibPatching(object):

    def test_urllib3_classes(self):
        assert issubclass(cert_human.HTTPSConnectionWithCertCls, urllib3.connection.HTTPSConnection)
        assert issubclass(cert_human.ResponseWithCertCls, urllib3.response.HTTPResponse)

    def test_enable_urllib3_patch(self, httpbin_secure, httpbin_cert):
        cert_human.enable_urllib3_patch()
        r = requests.get(httpbin_secure(), verify=httpbin_cert)
        assert getattr(r.raw, "peer_cert", None)
        assert getattr(r.raw, "peer_cert_chain", None)
        assert getattr(r.raw, "peer_cert_dict", None)
        cert_human.disable_urllib3_patch()

    def test_disable_urllib3_patch(self, httpbin_secure, httpbin_cert):
        cert_human.disable_urllib3_patch()
        r = requests.get(httpbin_secure(), verify=httpbin_cert)
        assert not getattr(r.raw, "peer_cert", None)
        assert not getattr(r.raw, "peer_cert_chain", None)
        assert not getattr(r.raw, "peer_cert_dict", None)

    def test_urllib3_patch(self, httpbin_secure, httpbin_cert):
        with cert_human.urllib3_patch():
            r = requests.get(httpbin_secure(), verify=httpbin_cert)
            assert getattr(r.raw, "peer_cert", None)
            assert getattr(r.raw, "peer_cert_chain", None)
            assert getattr(r.raw, "peer_cert_dict", None)
        r = requests.get(httpbin_secure(), verify=httpbin_cert)
        assert not getattr(r.raw, "peer_cert", None)
        assert not getattr(r.raw, "peer_cert_chain", None)
        assert not getattr(r.raw, "peer_cert_dict", None)

    def test_using_urllib3_patch(self):
        with cert_human.urllib3_patch():
            assert cert_human.using_urllib3_patch()
        assert not cert_human.using_urllib3_patch()

    def test_check_urllib3_patch(self):
        with cert_human.urllib3_patch():
            cert_human.check_urllib3_patch()

    def test_not_check_urllib3_patch(self):
        with pytest.raises(cert_human.CertHumanError):
            cert_human.check_urllib3_patch()


class TestGetCerts(object):

    def test_test_cert_invalid(self, httpbin_secure):
        valid, exc = cert_human.test_cert(host=httpbin_secure())
        assert not valid
        assert isinstance(exc, requests.exceptions.SSLError)

    def test_test_cert_valid(self, httpbin_secure, httpbin_cert):
        valid, exc = cert_human.test_cert(host=httpbin_secure(), path=httpbin_cert)
        assert valid
        assert exc is None

    def test_get_response(self, httpbin_secure, httpbin_cert):
        with pytest.warns(None) as warning_records:
            r = cert_human.get_response(httpbin_secure())
        warning_records = [x for x in warning_records]
        assert not warning_records
        assert getattr(r.raw, "peer_cert", None)
        assert getattr(r.raw, "peer_cert_chain", None)
        assert getattr(r.raw, "peer_cert_dict", None)
        cert = r.raw.peer_cert
        subj = cert.get_subject().get_components()
        subj_cn = subj[0]
        assert subj_cn == (b"CN", b"example.com")

    def test_get_response_invalid_verify(self, httpbin_secure, httpbin_cert, other_cert):
        with pytest.raises(requests.exceptions.SSLError):
            cert_human.get_response(httpbin_secure(), verify=format(other_cert))

    def test_get_response_valid_verify(self, httpbin_secure, httpbin_cert):
        cert_human.get_response(httpbin_secure(), verify=httpbin_cert)

    def test_ssl_socket(self, httpbin_secure, httpbin_cert):
        parts = requests.compat.urlparse(httpbin_secure())
        host = parts.hostname
        port = parts.port
        with cert_human.ssl_socket(host=host, port=port) as sock:
            cert = sock.get_peer_certificate()
            cert_chain = sock.get_peer_cert_chain()
        subj = cert.get_subject().get_components()
        subj_cn = subj[0]
        assert subj_cn == (b"CN", b"example.com")
        assert len(cert_chain) == 1


class TestUtilities(object):

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

    def test_clsname(self):
        assert cert_human.clsname(str) == "str"
        assert cert_human.clsname(self) == "TestUtilities"
        assert cert_human.clsname(cert_human.CertStore) == "CertStore"

    def test_hexify_int(self):
        # some serial numbers have an odd length hex int
        i = 9833040086282421696121167723365753840
        hstr = "0765C64E74E591D68039CA2A847563F0"
        hnozstr = "765C64E74E591D68039CA2A847563F0"
        hspacestr = '07 65 C6 4E 74 E5 91 D6 80 39 CA 2A 84 75 63 F0'
        assert cert_human.hexify(i) == hstr
        assert cert_human.hexify(i, zerofill=False) == hnozstr
        assert cert_human.hexify(i, space=True) == hspacestr

    def test_hexify_bytes(self):
        i = b'\x00\x93\xce\xf7\xff\xed'
        hstr = "0093CEF7FFED"
        hnozstr = '0093CEF7FFED'
        hspacestr = '00 93 CE F7 FF ED'
        assert cert_human.hexify(i) == hstr
        assert cert_human.hexify(i, zerofill=False) == hnozstr
        assert cert_human.hexify(i, space=True) == hspacestr

    def test_indent(self):
        txt = "test1\ntest2\n"
        itxt = cert_human.indent(txt=txt)
        assert itxt == '    test1\n    test2'

    def test_indent2(self):
        txt = "test1\ntest2\n"
        itxt = cert_human.indent(txt=txt)
        assert itxt == '    test1\n    test2'

    def test_write_file(self, tmp_path):
        sub1 = tmp_path / "sub1"
        sub2 = sub1 / "sub2"
        path = sub2 / "file.txt"
        text = "abc\n123\n"
        ret_path = cert_human.write_file(path=path, text=text)
        assert sub1.is_dir()
        assert sub2.is_dir()
        assert path.is_file()
        assert ret_path.read_text() == text
        assert oct(sub2.stat()[stat.ST_MODE])[-4:] == "0700"
        assert oct(path.stat()[stat.ST_MODE])[-4:] == "0600"

    def test_read_file(self, example_cert):
        txt = cert_human.read_file(example_cert)
        assert "----" in txt

    def test_read_file_error(self, tmp_path):
        with pytest.raises(cert_human.CertHumanError):
            cert_human.read_file(tmp_path / "abc.def.ghi")

    def test_write_file_noprotect(self, tmp_path):
        sub1 = tmp_path / "sub1"
        sub2 = sub1 / "sub2"
        path = sub2 / "file.txt"
        text = "abc\n123\n"
        ret_path = cert_human.write_file(path=path, text=text, protect=False)
        assert ret_path.read_text() == text

    def test_write_overwrite(self, tmp_path):
        sub1 = tmp_path / "sub1"
        sub2 = sub1 / "sub2"
        path = sub2 / "file.txt"
        text1 = "abc\n123\n"
        cert_human.write_file(path=path, text=text1)
        text2 = "def\n\456\n"
        ret_path = cert_human.write_file(path=path, text=text2, overwrite=True)
        assert ret_path.read_text() == text2

    def test_write_file_parentfail(self, tmp_path):
        sub1 = tmp_path / "sub1"
        sub2 = sub1 / "sub2"
        path = sub2 / "file.txt"
        text = "abc\n123\n"
        with pytest.raises(cert_human.CertHumanError):
            cert_human.write_file(path=path, text=text, mkparent=False)

    def test_write_file_existsfail(self, tmp_path):
        sub1 = tmp_path / "sub1"
        sub2 = sub1 / "sub2"
        path = sub2 / "file.txt"
        text = "abc\n123\n"
        cert_human.write_file(path=path, text=text)
        with pytest.raises(cert_human.CertHumanError):
            cert_human.write_file(path=path, text=text)

    def test_write_file_noperm_parent(self):
        tmpdir = cert_human.pathlib.Path(tempfile.gettempdir())
        path = tmpdir / "file.txt"
        text = "abc\n123\n"
        ret_path = cert_human.write_file(path=path, text=text, overwrite=True)
        assert ret_path.read_text() == text

    def test_find_certs(self, example_cert, other_cert):
        example_cert_txt = example_cert.read_text()
        other_cert_txt = other_cert.read_text()
        combo_txt = "\n".join([example_cert_txt, other_cert_txt])
        mixed_txt = "{0}\nother\ngobbledy\ngook\nhere\n{1}\n{0}"
        mixed_txt = mixed_txt.format(example_cert_txt, other_cert_txt)

        example_cert_list = cert_human.find_certs(example_cert_txt)
        other_cert_list = cert_human.find_certs(other_cert_txt)
        combo_list = cert_human.find_certs(combo_txt)
        mixed_list = cert_human.find_certs(mixed_txt)
        assert len(example_cert_list) == 1
        assert len(other_cert_list) == 1
        assert len(combo_list) == 2
        assert len(mixed_list) == 3
        for lst in [combo_list, mixed_list, example_cert_list, other_cert_list]:
            for crt in lst:
                assert crt.startswith("-----")
                assert crt.endswith("-----")

    def test_pem_to_x509(self, example_cert):
        example_cert_txt = example_cert.read_text()
        x509 = cert_human.pem_to_x509(example_cert_txt)
        assert isinstance(x509, OpenSSL.crypto.X509)
        subj = x509.get_subject().get_components()
        subj_cn = subj[0]
        assert subj_cn == (b"CN", b"example.com")

    def test_pems_to_x509(self, example_cert):
        example_cert_txt = example_cert.read_text()
        x509s = cert_human.pems_to_x509(example_cert_txt)
        assert len(x509s) == 1
        assert isinstance(x509s[0], OpenSSL.crypto.X509)
        subj = x509s[0].get_subject().get_components()
        subj_cn = subj[0]
        assert subj_cn == (b"CN", b"example.com")

    def test_x509_to_pem(self, example_cert):
        example_cert_txt = example_cert.read_text()
        x509 = cert_human.pem_to_x509(example_cert_txt)
        back_again = cert_human.x509_to_pem(x509)
        assert example_cert_txt == back_again

    def test_x509_to_der(self, example_cert):
        example_cert_txt = example_cert.read_text()
        x509 = cert_human.pem_to_x509(example_cert_txt)
        back_again = cert_human.x509_to_der(x509)
        assert isinstance(back_again, six.binary_type)

    def test_x509_to_asn1(self, example_cert):
        example_cert_txt = example_cert.read_text()
        x509 = cert_human.pem_to_x509(example_cert_txt)
        back_again = cert_human.x509_to_asn1(x509)
        assert isinstance(back_again, asn1crypto.x509.Certificate)
        assert back_again.subject.native == dict(common_name='example.com')

    def test_der_to_asn1(self, example_cert):
        example_cert_txt = example_cert.read_text()
        x509 = cert_human.pem_to_x509(example_cert_txt)
        der = cert_human.x509_to_der(x509)
        asn1 = cert_human.der_to_asn1(der)
        assert isinstance(asn1, asn1crypto.x509.Certificate)
        assert asn1.subject.native == dict(common_name='example.com')


class TestCertStore(object):

    def test_init(self, example_cert):
        pem = example_cert.read_text()
        x509 = cert_human.pem_to_x509(pem)
        store = cert_human.CertStore(x509)
        assert "Subject: Common Name: example.com" in format(store)
        assert "Subject: Common Name: example.com" in repr(store)
        assert pem == store.pem
        assert isinstance(store.der, six.binary_type)

    def test_from_socket(self, httpbin_secure, httpbin_cert):
        parts = requests.compat.urlparse(httpbin_secure())
        host = parts.hostname
        port = parts.port
        store = cert_human.CertStore.from_socket(host=host, port=port)
        assert "Subject: Common Name: example.com" in format(store)

    def test_from_request(self, httpbin_secure, httpbin_cert):
        parts = requests.compat.urlparse(httpbin_secure())
        host = parts.hostname
        port = parts.port
        store = cert_human.CertStore.from_request(host=host, port=port)
        assert "Subject: Common Name: example.com" in format(store)

    def test_from_response(self, httpbin_secure, httpbin_cert):
        r = cert_human.get_response(httpbin_secure())
        store = cert_human.CertStore.from_response(r)
        assert "Subject: Common Name: example.com" in format(store)

    def test_from_response_no_withcert(self, httpbin_secure, httpbin_cert):
        r = requests.get(httpbin_secure(), verify=False)
        with pytest.raises(cert_human.CertHumanError):
            cert_human.CertStore.from_response(r)

    def test_from_auto(self, httpbin_secure, httpbin_cert, example_cert):
        r = cert_human.get_response(httpbin_secure())
        auto_response = cert_human.CertStore.from_auto(r)
        store = cert_human.CertStore.from_path(example_cert)
        auto_asn1 = cert_human.CertStore.from_auto(store.asn1)
        auto_pem = cert_human.CertStore.from_auto(store.pem)
        auto_x509 = cert_human.CertStore.from_auto(store.x509)
        auto_der = cert_human.CertStore.from_auto(store.der)
        for i in [auto_asn1, auto_pem, auto_x509, auto_der, auto_response]:
            assert "Subject: Common Name: example.com" in format(i)

    def test_from_auto_bad(self):
        with pytest.raises(cert_human.CertHumanError):
            cert_human.CertStore.from_auto(None)
        with pytest.raises(cert_human.CertHumanError):
            cert_human.CertStore.from_auto('x')

    def test_from_path(self, example_cert):
        store = cert_human.CertStore.from_path(format(example_cert))
        assert "Subject: Common Name: example.com" in format(store)

    def test_to_path(self, example_cert):
        tmpdir = cert_human.pathlib.Path(tempfile.gettempdir())
        path = tmpdir / "sub3" / "sub4" / "cert.pem"
        store = cert_human.CertStore.from_path(example_cert)
        ret_path = store.to_path(path, overwrite=True)
        assert ret_path.read_text() == store.pem

    def test_issuer(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.issuer == {'common_name': 'example.com'}

    def test_subject(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.subject == {'common_name': 'example.com'}

    def test_subject_alt_names(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.subject_alt_names == ['example.com', 'example.net', 'localhost', '127.0.0.1']

    def test_subject_alt_names_none(self, httpbin_builtin_cert):
        store = cert_human.CertStore.from_path(httpbin_builtin_cert)
        assert store.subject_alt_names == []

    def test_public_key(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert len(store.public_key) >= 20
        assert store.public_key.isupper()
        store = cert_human.CertStore.from_path(ec_cert)
        assert len(store.public_key) >= 20
        assert store.public_key.isupper()

    def test_public_key_str(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert " " in store.public_key_str
        assert "\n" in store.public_key_str
        assert store.public_key_str.isupper()
        store = cert_human.CertStore.from_path(ec_cert)
        assert " " in store.public_key_str
        assert "\n" in store.public_key_str
        assert store.public_key_str.isupper()

    def test_public_key_parameters(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert not store.public_key_parameters
        store = cert_human.CertStore.from_path(ec_cert)
        assert store.public_key_parameters

    def test_public_key_size(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.public_key_size == 4096
        store = cert_human.CertStore.from_path(ec_cert)
        assert store.public_key_size == 256

    def test_public_key_exponent(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.public_key_exponent == 65537
        store = cert_human.CertStore.from_path(ec_cert)
        assert store.public_key_exponent is None

    def test_signature(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert len(store.signature) >= 20
        assert store.signature.isupper()

    def test_signature_str(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert " " in store.signature_str
        assert "\n" in store.signature_str
        assert store.signature_str.isupper()

    def test_signature_algorithm(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.signature_algorithm == "sha256_rsa"

    def test_x509_version(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.x509_version == "v3"

    def test_serial_number(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.serial_number.isupper()
        store = cert_human.CertStore.from_path(ec_cert)
        assert isinstance(store.serial_number, six.integer_types)

    def test_serial_number_str(self, ec_cert, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert " " in store.serial_number_str
        assert store.serial_number_str.isupper()
        store = cert_human.CertStore.from_path(ec_cert)
        assert isinstance(store.serial_number_str, (six.integer_types))

    def test_is_expired(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.is_expired is False

    def test_is_self_issued(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.is_self_issued is True

    def test_is_self_signed(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.is_self_signed == 'maybe'

    def test_not_valid_before(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert isinstance(store.not_valid_before, datetime.datetime)

    def test_not_valid_after(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert isinstance(store.not_valid_after, datetime.datetime)

    def test_not_valid_before_str(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert isinstance(store.not_valid_before_str, six.string_types)

    def test_not_valid_after_str(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert isinstance(store.not_valid_after_str, six.string_types)

    def test_extensions(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.extensions == {
            'subjectAltName':
            'DNS:example.com, DNS:example.net, DNS:localhost, IP Address:127.0.0.1',
        }

    def test_extensions_str(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.extensions_str == (
            'Extension 1, name=subjectAltName, value=DNS:example.com, DNS:example.net, '
            'DNS:localhost, IP Address:127.0.0.1'
        )

    def test_dump(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.dump["subject"] == {'common_name': 'example.com'}

    def test_dump_json_friendly(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert all([
            isinstance(v, (dict, six.string_types, six.integer_types, list, bool, type(None)))
            for v in store.dump_json_friendly.values()
        ])

    def test_dump_json(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        dump = json.loads(store.dump_json)
        assert '"subject": {\n    "common_name": "example.com"\n' in store.dump_json
        assert isinstance(dump, dict)

    def test_dump_str(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert 'Subject: Common Name: example.com\n' in store.dump_str

    def test_dump_str_exts(self, example_cert):
        store = cert_human.CertStore.from_path(example_cert)
        assert store.dump_str_exts == (
            'Extensions:\n    Extension 1, name=subjectAltName, '
            'value=DNS:example.com, DNS:example.net, DNS:localhost, IP Address:127.0.0.1'
        )


class TestChainCertStore(object):

    def test_init(self, example_cert, other_cert, ec_cert):
        example_pem = example_cert.read_text()
        other_pem = other_cert.read_text()
        ec_pem = ec_cert.read_text()
        x509s = [
            cert_human.pem_to_x509(example_pem),
            cert_human.pem_to_x509(other_pem),
            cert_human.pem_to_x509(ec_pem),
        ]
        store = cert_human.CertChainStore(x509s)
        assert len(store) == 3
        assert store[0].x509 == x509s[0]
        assert "Subject: Common Name: example.com" in format(store)
        assert "Subject: Common Name: otherexample.com" in format(store)
        assert "Subject: Common Name: ecexample.com" in format(store)
        assert "Subject: Common Name: example.com" in repr(store)

    def test_append(self, example_cert, ec_cert, other_cert):
        example_store = cert_human.CertStore.from_path(example_cert)
        other_store = cert_human.CertStore.from_path(other_cert)
        ec_store = cert_human.CertStore.from_path(ec_cert)

        store = cert_human.CertChainStore([])
        store.append(example_store.x509)
        store.append(other_store)
        store.append(ec_store.pem)
        assert len(store) == 3

    def test_from_socket(self, httpbin_secure, httpbin_cert):
        parts = requests.compat.urlparse(httpbin_secure())
        host = parts.hostname
        port = parts.port
        store = cert_human.CertChainStore.from_socket(host=host, port=port)
        assert len(store) == 1
        assert "Subject: Common Name: example.com" in format(store[0])

    def test_from_request(self, httpbin_secure, httpbin_cert):
        parts = requests.compat.urlparse(httpbin_secure())
        host = parts.hostname
        port = parts.port
        store = cert_human.CertChainStore.from_request(host=host, port=port)
        assert len(store) == 1
        assert "Subject: Common Name: example.com" in format(store[0])

    def test_from_response(self, httpbin_secure, httpbin_cert):
        r = cert_human.get_response(httpbin_secure())
        store = cert_human.CertChainStore.from_response(r)
        assert len(store) == 1
        assert "Subject: Common Name: example.com" in format(store[0])

    def test_from_response_no_withcert(self, httpbin_secure, httpbin_cert):
        r = requests.get(httpbin_secure(), verify=False)
        with pytest.raises(cert_human.CertHumanError):
            cert_human.CertChainStore.from_response(r)

    def test_from_pem(self, example_cert, other_cert):
        example_pem = example_cert.read_text()
        other_pem = other_cert.read_text()
        pems = "\n".join([example_pem, other_pem])
        store = cert_human.CertChainStore.from_pem(pems)
        assert len(store) == 2
        assert "Subject: Common Name: example.com" in format(store[0])

    def test_from_path(self, example_cert):
        store = cert_human.CertChainStore.from_path(example_cert)
        assert len(store) == 1
        assert "Subject: Common Name: example.com" in format(store[0])
        assert len(store.certs) == 1
        assert len(cert_human.find_certs(store.pem)) == 1
        assert len(store.x509) == 1
        assert len(store.der) == 1
        assert len(store.asn1) == 1

    def test_to_path(self, example_cert):
        tmpdir = cert_human.pathlib.Path(tempfile.gettempdir())
        path = tmpdir / "sub3" / "sub4" / "cert.pem"
        store = cert_human.CertChainStore.from_path(example_cert)
        ret_path = store.to_path(path, overwrite=True)
        assert ret_path.read_text() == store.pem

    def test_dumps(self, example_cert):
        store = cert_human.CertChainStore.from_path(example_cert)
        dumps = [
            store.dump_json_friendly,
            store.dump,
        ]
        for d in dumps:
            assert isinstance(d, list)
            assert len(d) == 1

    def test_dumps_str(self, example_cert):
        store = cert_human.CertChainStore.from_path(example_cert)
        dumps = [
            store.dump_str,
            store.dump_str_info,
            store.dump_str_exts,
            store.dump_str_key,
        ]
        for d in dumps:
            assert isinstance(d, six.string_types)
            assert "CertStore #1" in d.splitlines()[1]

    def test_dump_json(self, example_cert):
        store = cert_human.CertChainStore.from_path(example_cert)
        dump = json.loads(store.dump_json)
        assert isinstance(dump, list)
        assert len(dump) == 1
