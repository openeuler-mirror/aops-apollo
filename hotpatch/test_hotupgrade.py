#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
import unittest
from unittest import mock

from .updateinfo_parse import HotpatchUpdateInfo
from .hotupgrade import HotupgradeCommand


class UpgradeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        cli = mock.MagicMock()
        self.cmd = HotupgradeCommand(cli)

    @mock.patch.object(HotpatchUpdateInfo, "get_hotpatches_from_cve")
    def test_get_hotpatch_based_on_cve_should_return_empty_list_when_no_patch_found(self, mock_patch):
        mock_patch.return_value = {"CVE-2022-1": ["patch-kernel-4.19-1-ACC-1-1"],
                                   "CVE-2022-2": ["patch-kernel-4.19-1-ACC-1-1"]}
        res = self.cmd.get_hotpatch_based_on_cve(["CVE-2022-3"])
        expected_res = []
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotpatchUpdateInfo, "get_hotpatches_from_cve")
    def test_get_hotpatch_based_on_cve_should_return_correct_when_two_cve_have_same_patch(self, mock_patch):
        mock_patch.return_value = {"CVE-2022-1": ["patch-kernel-4.19-1-ACC-1-1"],
                                   "CVE-2022-2": ["patch-kernel-4.19-1-ACC-1-1", "patch-kernel-tools-4.19-1-ACc-1-1"]}
        res = self.cmd.get_hotpatch_based_on_cve(["CVE-2022-1", "CVE-2022-2"])
        expected_res = ["patch-kernel-4.19-1-ACC-1-1", "patch-kernel-tools-4.19-1-ACc-1-1"]
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotpatchUpdateInfo, "get_hotpatches_from_advisories")
    def test_get_hotpatch_based_on_advisory_should_return_empty_list_when_no_patch_found(self, mock_patch):
        mock_patch.return_value = {"SA-2022-1": ["patch-kernel-4.19-1-ACC-1-1"],
                                   "SA-2022-2": ["patch-kernel-4.19-1-ACC-1-1"]}
        res = self.cmd.get_hotpatch_based_on_advisory(["SA-2022-3"])
        expected_res = []
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotpatchUpdateInfo, "get_hotpatches_from_advisories")
    def test_get_hotpatch_based_on_advisory_should_return_correct_when_two_cve_have_same_patch(self, mock_patch):
        mock_patch.return_value = {"SA-2022-1": ["patch-kernel-4.19-1-ACC-1-1"],
                                   "SA-2022-2": ["patch-kernel-4.19-1-ACC-1-1", "patch-kernel-tools-4.19-1-ACc-1-1"]}
        res = self.cmd.get_hotpatch_based_on_cve(["SA-2022-2"])
        expected_res = ["patch-kernel-4.19-1-ACC-1-1", "patch-kernel-tools-4.19-1-ACc-1-1"]
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotpatchUpdateInfo, "get_hotpatch_of_all_cve")
    def test_get_hotpatch_of_all_cve_should_return_empty_list_when_no_patch_found(self, mock_patch):
        mock_patch.return_value = {"CVE-2022-1": [],
                                   "CVE-2022-2": []}
        res = self.cmd.get_hotpatch_of_all_cve()
        expected_res = []
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotpatchUpdateInfo, "get_hotpatch_of_all_cve")
    def test_get_hotpatch_of_all_cve_should_return_correct_when_two_cve_have_same_patch(self, mock_patch):
        mock_patch.return_value = {"CVE-2022-1": ["patch-kernel-4.19-1-ACC-1-1"],
                                   "CVE-2022-2": ["patch-kernel-4.19-1-ACC-1-1", "patch-kernel-tools-4.19-1-ACc-1-1"]}
        res = self.cmd.get_hotpatch_of_all_cve()
        expected_res = ["patch-kernel-4.19-1-ACC-1-1", "patch-kernel-tools-4.19-1-ACc-1-1"]
        self.assertEqual(res, expected_res)


if __name__ == '__main__':
    unittest.main()
