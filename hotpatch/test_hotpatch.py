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

from .hotpatch import HotpatchCommand
from .syscare import SUCCEED, FAIL


class HotpatchTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cli = mock.MagicMock()
        self.cmd = HotpatchCommand(self.cli)

    def test_operate_hot_patches_should_return_none(self):
        target_patch = ["patch1"]
        operate = mock.MagicMock()
        func = mock.MagicMock()
        func.return_value = ("", FAIL)
        self.assertIsNone(self.cmd.operate_hot_patches(target_patch, operate, func))
        self.assertEqual(self.cmd.base.output.term.bold.call_args_list[1][0][0], target_patch[0])

        func.return_value = ("", SUCCEED)
        self.assertIsNone(self.cmd.operate_hot_patches(target_patch, operate, func))
        self.assertEqual(self.cmd.base.output.term.bold.call_args_list[1][0][0], target_patch[0])

    def test_operate_hot_patches_should_return_none_when_target_patch_is_none(self):
        target_patch = []
        operate = "apply"
        func = mock.MagicMock()
        self.assertIsNone(self.cmd.operate_hot_patches(target_patch, operate, func))


if __name__ == '__main__':
    unittest.main()
