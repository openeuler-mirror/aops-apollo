import unittest
from unittest import mock
import dnf

from hotpatch.hotupgrade import HotupgradeCommand
from hotpatch.hotpatch_updateinfo import HotpatchUpdateInfo
from hotpatch.hot_updateinfo import HotUpdateinfoCommand, DisplayItem


class UpgradeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        cli = mock.MagicMock()
        self.cmd = HotupgradeCommand(cli)

    @mock.patch.object(HotupgradeCommand, "get_hot_updateinfo_list")
    def test_upgrade_all_when_return_patch_is_empty(self, mock_remove):
        mock_remove.return_value = []
        res = self.cmd.upgrade_all()
        expected_res = []
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotupgradeCommand, "get_hot_updateinfo_list")
    def test_upgrade_all_when_return_patch_is_not_empty(self, mock_remove):
        mock_remove.return_value = ['patch-name1-6.2.5-1-HP002-1-1.x86_64', 'patch-name1-6.2.5-1-HP001-1-1.x86_64',
                                    'patch-name2-6.2.5-1-HP001-1-1.x86_64', '-',
                                    '-']
        res = self.cmd.upgrade_all()
        expected_res = ['patch-name2-6.2.5-1-HP001-1-1.x86_64', 'patch-name1-6.2.5-1-HP002-1-1.x86_64']
        self.assertEqual(res, expected_res)

    @mock.patch.object(HotUpdateinfoCommand, "get_formatting_parameters_and_display_lines")
    def test_get_hot_updateinfo_list(self, mock_cve):
        self.cmd.cli.base = dnf.cli.cli.BaseCli()
        self.cmd.cli.base._sack = mock.MagicMock()

        self.cmd.opts = mock.MagicMock()
        self.cmd.hp_hawkey = HotpatchUpdateInfo(self.cmd.cli.base, self.cmd.cli)
        self.cmd.filter_cves = None
        mock_cve.return_value = DisplayItem(idw=14, tiw=14, ciw=51,
                                            display_lines=[('CVE-2023-3331', 'Low/Sec.', '-', '-'), (
                                                'CVE-2023-1112', 'Important/Sec.', '-',
                                                'patch-redis-6.2.5-1-HP001-1-1.x86_64')])
        res = self.cmd.get_hot_updateinfo_list()
        expected_res = ['-', 'patch-redis-6.2.5-1-HP001-1-1.x86_64']
        self.assertEqual(res, expected_res)


if __name__ == '__main__':
    unittest.main()
