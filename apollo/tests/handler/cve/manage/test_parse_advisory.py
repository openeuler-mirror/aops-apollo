#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
"""
Time:
Author:
Description:
"""
import os
import unittest

from apollo.handler.cve_handler.manager.parse_advisory import parse_security_advisory
from apollo.function.customize_exception import ParseAdvisoryError


class TestParseAdvisory(unittest.TestCase):
    def setUp(self) -> None:
        self.resource = os.path.join(os.path.dirname(__file__), "resource")

    def test_parse_security_advisory_should_return_exception_when_not_valid_xml(self):
        error_format_file = os.path.join(self.resource, "error-format.xml")
        self.assertRaises(ParseAdvisoryError, parse_security_advisory, error_format_file)

    def test_parse_security_advisory_should_return_right_cve_when_valid_format_xml(self):
        security_advisory = os.path.join(self.resource, "openEuler-SA-2023-1001.xml")
        cve_rows, _, _, _, _ = parse_security_advisory(security_advisory)
        self.assertEqual(len(cve_rows), 1)
        self.assertEqual(cve_rows[-1]["cve_id"], "CVE-2022-44940")

    def test_parse_security_advisory_should_return_exception_when_exists_repeat_cve(self):
        security_advisory = os.path.join(self.resource, "repeat-SA.xml")
        self.assertRaises(ParseAdvisoryError, parse_security_advisory, security_advisory)
