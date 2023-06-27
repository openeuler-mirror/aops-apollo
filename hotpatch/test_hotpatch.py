import unittest
from unittest import mock

from hotpatch.hotpatch import HotpatchCommand
from hotpatch.syscare import SUCCEED, FAIL


class HotpatchTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cli = mock.MagicMock()
        self.cmd = HotpatchCommand(self.cli)

    def test_operate_hot_patches_when_func_return_fail(self):
        target_patch = ["redis-6.2.5-1/HP2"]
        operate = "apply"
        func = mock.MagicMock()
        func.return_value = ("", FAIL)
        self.assertIsNone(self.cmd.operate_hot_patches(target_patch, operate, func))
        func.assert_called_once_with(target_patch[0])
        self.assertEqual(self.cmd.base.output.term.bold.call_args_list[1][0][0],
                         target_patch[0])

    def test_operate_hot_patches_when_func_return_succeed(self):
        target_patch = ["redis-6.2.5-1/HP2"]
        operate = "apply"
        func = mock.MagicMock()
        func.return_value = ("", SUCCEED)
        self.assertIsNone(self.cmd.operate_hot_patches(target_patch, operate, func))
        func.assert_called_once_with(target_patch[0])
        self.assertEqual(self.cmd.base.output.term.bold.call_args_list[1][0][0],
                         target_patch[0])

    def test_operate_hot_patches_when_target_patch_is_none(self):
        target_patch = []
        operate = "apply"
        func = mock.MagicMock()
        self.assertIsNone(self.cmd.operate_hot_patches(target_patch, operate, func))


if __name__ == '__main__':
    unittest.main()
