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
import dnf

from .hotupgrade import HotupgradeCommand
from .hotpatch_updateinfo import HotpatchUpdateInfo
from .hot_updateinfo import HotUpdateinfoCommand, DisplayItem


class UpgradeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        cli = mock.MagicMock()
        self.cmd = HotupgradeCommand(cli)

    @mock.patch.object(HotupgradeCommand, "get_hot_updateinfo_list")
    def test_upgrade_all_should_return_none_when_patch_is_empty(self, mock_patch):
        mock_patch.return_value = []
        res = self.cmd.upgrade_all()
        expected_res = []
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotupgradeCommand, "get_hot_updateinfo_list")
    def test_upgrade_all_should_return_none_when_patch_is_empty_tag(self, mock_patch):
        mock_patch.return_value = ['-', '-']
        res = self.cmd.upgrade_all()
        expected_res = []
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotupgradeCommand, "get_hot_updateinfo_list")
    def test_upgrade_all_should_return_correct_when_patch_name_is_same(self, mock_patch):
        mock_patch.return_value = ['patch-name1-6.2.5-1-HP002-1-1.x86_64', 'patch-name1-6.2.5-1-HP001-1-1.x86_64']
        res = self.cmd.upgrade_all()
        expected_res = ['patch-name1-6.2.5-1-HP002-1-1.x86_64']
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotupgradeCommand, "get_hot_updateinfo_list")
    def test_upgrade_all_should_return_correct(self, mock_patch):
        mock_patch.return_value = ['patch-name1-6.2.5-1-HP002-1-1.x86_64', 'patch-name1-6.2.5-1-HP001-1-1.x86_64',
                                   'patch-name2-6.2.5-1-HP001-1-1.x86_64', '-']
        res = self.cmd.upgrade_all()
        expected_res = ['patch-name2-6.2.5-1-HP001-1-1.x86_64', 'patch-name1-6.2.5-1-HP002-1-1.x86_64']
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotUpdateinfoCommand, "get_formatting_parameters_and_display_lines")
    def test_get_hot_updateinfo_list_should_return_correct(self, mock_cve):
        self.cmd.cli.base = dnf.cli.cli.BaseCli()
        self.cmd.cli.base._sack = mock.MagicMock()

        self.cmd.opts = mock.MagicMock()
        self.cmd.hp_hawkey = HotpatchUpdateInfo(self.cmd.cli.base, self.cmd.cli)
        self.cmd.filter_cves = None
        mock_cve.return_value = DisplayItem(idw=0, tiw=0, ciw=0,
                                            display_lines=[('CVE-2023-3331', 'Low/Sec.', '-', '-'), (
                                                'CVE-2023-1112', 'Important/Sec.', '-',
                                                'patch-redis-6.2.5-1-HP001-1-1.x86_64')])
        res = self.cmd.get_hot_updateinfo_list()
        expected_res = ['-', 'patch-redis-6.2.5-1-HP001-1-1.x86_64']
        self.assertEqual(res, expected_res)


if __name__ == '__main__':
    unittest.main()
