# -*- coding: utf-8 -*-
"""Test suite for cert_human."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import cert_human


class TestCertHuman:

    def test_entry_points(self):
        cert_human.CertStore
        cert_human.CertChainStore
