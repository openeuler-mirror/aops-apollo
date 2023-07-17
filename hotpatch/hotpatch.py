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
import dnf
from dnfpluginscore import _, logger

from .hotpatch_updateinfo import HotpatchUpdateInfo
from .syscare import Syscare


@dnf.plugin.register_command
class HotpatchCommand(dnf.cli.Command):
    aliases = ['hotpatch']
    summary = _('show hotpatch info')
    syscare = Syscare()

    def __init__(self, cli):
        """
        Initialize the command
        """
        super(HotpatchCommand, self).__init__(cli)

    @staticmethod
    def set_argparser(parser):
        output_format = parser.add_mutually_exclusive_group()
        output_format.add_argument(
            '--list', nargs='?', type=str, default='', choices=['cve', 'cves'], help=_('show list of hotpatch')
        )
        output_format.add_argument(
            '--apply', type=str, default=None, dest='apply_name', nargs=1, help=_('apply hotpatch')
        )
        output_format.add_argument(
            '--remove', type=str, default=None, dest='remove_name', nargs=1, help=_('remove hotpatch')
        )
        output_format.add_argument(
            '--active', type=str, default=None, dest='active_name', nargs=1, help=_('active hotpatch')
        )
        output_format.add_argument(
            '--deactive', type=str, default=None, dest='deactive_name', nargs=1, help=_('deactive hotpatch')
        )
        output_format.add_argument(
            '--accept', type=str, default=None, dest='accept_name', nargs=1, help=_('accept hotpatch')
        )

    def configure(self):
        demands = self.cli.demands
        demands.sack_activation = True
        demands.available_repos = True

        self.filter_cves = self.opts.cves if self.opts.cves else None

    def run(self):
        self.hp_hawkey = HotpatchUpdateInfo(self.cli.base, self.cli)
        if self.opts.list != '':
            self.display()
        if self.opts.apply_name:
            self.operate_hot_patches(self.opts.apply_name, "apply", self.syscare.apply)
        if self.opts.remove_name:
            self.operate_hot_patches(self.opts.remove_name, "remove", self.syscare.remove)
        if self.opts.active_name:
            self.operate_hot_patches(self.opts.active_name, "active", self.syscare.active)
        if self.opts.deactive_name:
            self.operate_hot_patches(self.opts.deactive_name, "deactive", self.syscare.deactive)
        if self.opts.accept_name:
            self.operate_hot_patches(self.opts.accept_name, "accept", self.syscare.accept)

    def _filter_and_format_list_output(self, echo_lines: list):
        """
        Only show specific cve information if cve id is given, and format the output.
        """
        format_lines = []
        title = ['CVE-id', 'base-pkg/hotpatch', 'status']
        idw = len(title[0])
        naw = len(title[1])
        for echo_line in echo_lines:
            cve_id, name, status = echo_line[0], echo_line[1], echo_line[2]
            if self.filter_cves is not None and cve_id not in self.filter_cves:
                continue
            idw = max(idw, len(cve_id))
            naw = max(naw, len(name))
            format_lines.append([cve_id, name, status])

        if not format_lines:
            return

        # print title
        if self.opts.list in ['cve', 'cves']:
            print('%-*s %-*s %s' % (idw, title[0], naw, title[1], title[2]))
        else:
            print('%-*s %s' % (naw, title[1], title[2]))

        for format_line in sorted(format_lines, key=lambda x: (x[1], x[0])):
            if self.opts.list in ['cve', 'cves']:
                print('%-*s %-*s %s' % (idw, format_line[0], naw, format_line[1], format_line[2]))
            else:
                print('%-*s %s' % (naw, format_line[1], format_line[2]))

    def display(self):
        """
        Display hotpatch information.

        e.g.
        For the command of 'dnf hotpatch --list', the echo_lines is [[base-pkg/hotpatch, status], ...]
        For the command of 'dnf hotpatch --list cve', the echo_lines is [[cve_id, base-pkg/hotpatch, status], ...]
        """
        hotpatch_cves = self.hp_hawkey.hotpatch_cves
        echo_lines = []
        for cve_id in hotpatch_cves.keys():
            for hotpatch in hotpatch_cves[cve_id].hotpatches:
                status = self.hp_hawkey._get_hotpatch_status_in_syscare(hotpatch)
                if status == '':
                    continue
                echo_line = [cve_id, hotpatch.syscare_name, status]
                echo_lines.append(echo_line)

        self._filter_and_format_list_output(echo_lines)

    def operate_hot_patches(self, target_patch: list, operate, func) -> None:
        """
        operate hotpatch using syscare command
        Args:
            target_patch: type:list,e.g.:['redis-6.2.5-1/HP2']

        Returns:
            None
        """
        if len(target_patch) != 1:
            logger.error(_("using dnf hotpatch --%s wrong!"), operate)
            return
        target_patch = target_patch[0]
        logger.info(_("Gonna %s this hot patch: %s"), operate, self.base.output.term.bold(target_patch))

        output, status = func(target_patch)
        if status:
            logger.error(
                _("%s hot patch '%s' failed, remain original status."),
                operate,
                self.base.output.term.bold(target_patch),
            )
        else:
            logger.info(_("%s hot patch '%s' succeed"), operate, self.base.output.term.bold(target_patch))
