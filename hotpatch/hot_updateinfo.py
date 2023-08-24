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
import hawkey
from dnf.i18n import _
from dnf.cli.commands.updateinfo import UpdateInfoCommand
from dataclasses import dataclass
from .updateinfo_parse import HotpatchUpdateInfo
from .version import Versions


@dataclass
class DisplayItem:
    """
    Class for storing the formatting parameters and display lines.

    idw: the width of 'cve_id'
    tiw: the width of 'adv_type'
    ciw: the width of 'coldpatch'
    display_lines: [
            [cve_id, adv_type, coldpatch, hotpatch],
        ]
    """

    idw: int
    tiw: int
    ciw: int
    display_lines: set


@dnf.plugin.register_command
class HotUpdateinfoCommand(dnf.cli.Command):
    CVE_ID_INDEX = 0
    ADV_SEVERITY_INDEX = 1
    COLDPATCH_INDEX = 2
    HOTPATCH_INDEX = 3

    aliases = ['hot-updateinfo']
    summary = _('show hotpatch updateinfo')

    def __init__(self, cli):
        """
        Initialize the command
        """
        super(HotUpdateinfoCommand, self).__init__(cli)

    @staticmethod
    def set_argparser(parser):
        spec_action_cmds = ['list']
        parser.add_argument('spec_action', nargs=1, choices=spec_action_cmds, help=_('show updateinfo list'))

        with_cve_cmds = ['cve', 'cves']
        parser.add_argument('with_cve', nargs=1, choices=with_cve_cmds, help=_('show cves'))

    def configure(self):
        demands = self.cli.demands
        demands.sack_activation = True
        demands.available_repos = True

        self.filter_cves = self.opts.cves if self.opts.cves else None

    def run(self):
        self.hp_hawkey = HotpatchUpdateInfo(self.cli.base, self.cli)

        if self.opts.spec_action and self.opts.spec_action[0] == 'list' and self.opts.with_cve:
            self.display()

    def get_mapping_nevra_cve(self) -> dict:
        """
        Get cve nevra mapping based on the UpdateInfoCommand of 'dnf updateinfo list cves'

        Returns:
        {
            (nevra, advisory.updated): {
                cve_id: (advisory.type, advisory.severity)
                ...
            }
            ...
        }
        """

        apkg_adv_insts = self.get_available_apkg_adv_insts()

        mapping_nevra_cve = dict()
        for apkg, advisory, _ in apkg_adv_insts:
            nevra = (apkg.name, apkg.evr, apkg.arch)
            for ref in advisory.references:
                if ref.type != hawkey.REFERENCE_CVE:
                    continue
                mapping_nevra_cve.setdefault((nevra, advisory.updated), dict())[ref.id] = (
                    advisory.type,
                    advisory.severity,
                )
        return mapping_nevra_cve

    def get_available_apkg_adv_insts(self):
        """
        Configure UpdateInfoCommand with 'dnf updateinfo list cves', and get available package, advisory
        and package installation information.
        """
        updateinfo = UpdateInfoCommand(self.cli)
        updateinfo.opts = self.opts

        updateinfo.opts.spec_action = 'list'
        updateinfo.opts.with_cve = True
        updateinfo.opts.spec = '*'
        updateinfo.opts._advisory_types = set()
        updateinfo.opts.availability = 'available'
        self.updateinfo = updateinfo

        apkg_adv_insts = updateinfo.available_apkg_adv_insts(updateinfo.opts.spec)
        return apkg_adv_insts

    def _filter_and_format_list_output(self, echo_lines: list, fixed_cve_id_and_hotpatch: set):
        """
        Only show specified cve information that have not been fixed, and format the display lines

        Returns:
            DisplayItem
        """
        format_lines = set()
        for echo_line in echo_lines:
            cve_id, adv_type, coldpatch, hotpatch = (
                echo_line[self.CVE_ID_INDEX],
                echo_line[self.ADV_SEVERITY_INDEX],
                echo_line[self.COLDPATCH_INDEX],
                echo_line[self.HOTPATCH_INDEX],
            )
            if self.filter_cves is not None and cve_id not in self.filter_cves:
                continue
            if not isinstance(coldpatch, str):
                pkg_name, pkg_evr, pkg_arch = coldpatch
                coldpatch = '%s-%s.%s' % (pkg_name, pkg_evr, pkg_arch)
            format_lines.add((cve_id, adv_type, coldpatch, hotpatch))

        display_item = self.get_filtered_display_item(format_lines, fixed_cve_id_and_hotpatch)

        return display_item

    def get_fixed_cve_id_and_hotpatch_require_info(self, fixed_cve_id_and_hotpatch: set):
        """
        Get fixed cve id and hotpatch require package information.

        Returns:
            fixed_cve_id_and_hotpatch_require_info
        """
        fixed_cve_id_and_hotpatch_require_info = set()
        for fixed_cve_id, fixed_hotpatch in fixed_cve_id_and_hotpatch:
            fixed_cve_id_and_hotpatch_require_info.add((fixed_cve_id, fixed_hotpatch.required_pkgs_str))
        return fixed_cve_id_and_hotpatch_require_info

    def get_filtered_display_item(self, format_lines: set, fixed_cve_id_and_hotpatch: set):
        """
        Get filtered display item by removing fixed cve id and hotpatch.

        Returns:
            DisplayItem
        """
        display_lines = set()
        fixed_cve_id_and_hotpatch = self.append_fixed_cve_id_and_hotpatch(fixed_cve_id_and_hotpatch)

        fixed_cve_id_and_hotpatch_require_info = self.get_fixed_cve_id_and_hotpatch_require_info(
            fixed_cve_id_and_hotpatch
        )

        # calculate the width of each column
        idw = tiw = ciw = 0
        for format_line in format_lines:
            cve_id, adv_type, coldpatch, hotpatch = (
                format_line[self.CVE_ID_INDEX],
                format_line[self.ADV_SEVERITY_INDEX],
                format_line[self.COLDPATCH_INDEX],
                format_line[self.HOTPATCH_INDEX],
            )
            if (cve_id, hotpatch) in fixed_cve_id_and_hotpatch:
                continue
            if hotpatch != '-' and (cve_id, hotpatch.required_pkgs_str) in fixed_cve_id_and_hotpatch_require_info:
                continue

            idw = max(idw, len(cve_id))
            tiw = max(tiw, len(adv_type))
            ciw = max(ciw, len(coldpatch))
            if hotpatch != '-':
                hotpatch = hotpatch.nevra
            display_lines.add((cve_id, adv_type, coldpatch, hotpatch))

        display_lines = self.remove_redundant_display_line(display_lines)
        display_item = DisplayItem(idw=idw, tiw=tiw, ciw=ciw, display_lines=display_lines)
        return display_item

    def remove_redundant_display_line(self, display_lines: set):
        """
        Remove redundant display line. Do not echo the uninstallable hotpatch, if there is a installable
        hotpatch for the same cve and coldpatch.

        Returns:
            display_lines: set
        """
        redundanted_display_lines = set(display_lines)
        for display_line in display_lines:
            cve_id, adv_type, coldpatch, hotpatch = (
                display_line[self.CVE_ID_INDEX],
                display_line[self.ADV_SEVERITY_INDEX],
                display_line[self.COLDPATCH_INDEX],
                display_line[self.HOTPATCH_INDEX],
            )
            if hotpatch != '-' and (cve_id, adv_type, coldpatch, '-') in display_lines:
                redundanted_display_lines.discard((cve_id, adv_type, coldpatch, '-'))
            if hotpatch != '-' and coldpatch != '-' and (cve_id, adv_type, '-', '-') in display_lines:
                redundanted_display_lines.discard((cve_id, adv_type, '-', '-'))

        return redundanted_display_lines

    def append_fixed_cve_id_and_hotpatch(self, fixed_cve_id_and_hotpatch: set):
        """
        Append fixed cve id and hotpatch in fixed_cve_id_and_hotpatch. The hotpatch that are less or equal
        to the highest actived version-release for the same target required package, is considered to be
        fixed.

        Returns:
            fixed_cve_id_and_hotpatch
        """
        versions = Versions()
        # {hotpatch_required_pkgs_str: version-release}
        hotpatch_vere_mapping = dict()
        for _, fixed_hotpatch in fixed_cve_id_and_hotpatch:
            # get the highest version-release for each target required package
            required_pkgs_str = fixed_hotpatch.required_pkgs_str

            current_vere = "%s-%s" % (fixed_hotpatch.version, fixed_hotpatch.release)
            if required_pkgs_str not in hotpatch_vere_mapping:
                hotpatch_vere_mapping[required_pkgs_str] = current_vere
            elif versions.larger_than(hotpatch_vere_mapping[required_pkgs_str], current_vere):
                hotpatch_vere_mapping[required_pkgs_str] = current_vere

        # get all hot hotpatches that are less or equal to the highest version-release, and record the cves
        # which they fix
        for required_pkgs_str, actived_vere in hotpatch_vere_mapping.items():
            all_hotpatches = self.hp_hawkey._hotpatch_required_pkg_info_str[required_pkgs_str]
            for cmped_vere, hotpatch in all_hotpatches:
                if not versions.larger_than(actived_vere, cmped_vere):
                    continue
                for cve_id in hotpatch.cves:
                    fixed_cve_id_and_hotpatch.add((cve_id, hotpatch))
        return fixed_cve_id_and_hotpatch

    def get_formatting_parameters_and_display_lines(self):
        """
        Append hotpatch information according to the output of 'dnf updateinfo list cves'

        echo lines:
            [
                [cve_id, adv_type, coldpatch, hotpatch]
            ]

        Returns:
            DisplayItem
        """

        def type2label(updateinfo, typ, sev):
            if typ == hawkey.ADVISORY_SECURITY:
                return updateinfo.SECURITY2LABEL.get(sev, _('Unknown/Sec.'))
            else:
                return updateinfo.TYPE2LABEL.get(typ, _('unknown'))

        mapping_nevra_cve = self.get_mapping_nevra_cve()
        echo_lines = []
        fixed_cve_id_and_hotpatch = set()
        iterated_cve_id_and_hotpatch = set()

        for ((nevra), aupdated), id2type in sorted(mapping_nevra_cve.items(), key=lambda x: x[0]):
            pkg_name, pkg_evr, pkg_arch = nevra
            for cve_id, atypesev in id2type.items():
                label = type2label(self.updateinfo, *atypesev)
                if cve_id not in self.hp_hawkey.hotpatch_cves or not self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                    echo_line = [cve_id, label, nevra, '-']
                    echo_lines.append(echo_line)
                    continue

                for hotpatch in self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                    echo_line = [cve_id, label, nevra, '-']
                    if pkg_name not in hotpatch._required_pkgs_info.keys():
                        continue
                    iterated_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    echo_lines.append(echo_line)
                    if hotpatch.state == self.hp_hawkey.INSTALLED:
                        echo_lines.pop()
                        # record the fixed cve_id and hotpatch, filter the packages that are lower than
                        # the currently installed package for solving the same cve and target required
                        # pakcage
                        fixed_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                        echo_lines[-1][self.HOTPATCH_INDEX] = hotpatch

        self.add_untraversed_hotpatches(echo_lines, fixed_cve_id_and_hotpatch, iterated_cve_id_and_hotpatch)

        display_item = self._filter_and_format_list_output(echo_lines, fixed_cve_id_and_hotpatch)

        return display_item

    def add_untraversed_hotpatches(
        self, echo_lines: list, fixed_cve_id_and_hotpatch: set, iterated_cve_id_and_hotpatch: set
    ):
        """
        Add the echo lines, which are only with hotpatch but no coldpatch.
        """
        for cve_id, cve in self.hp_hawkey.hotpatch_cves.items():
            for hotpatch in cve.hotpatches:
                if (cve_id, hotpatch) in iterated_cve_id_and_hotpatch:
                    continue
                echo_line = [cve_id, hotpatch.advisory.severity + '/Sec.', '-', '-']
                if hotpatch.state == self.hp_hawkey.INSTALLED:
                    fixed_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    continue
                elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                    echo_line = [cve_id, hotpatch.advisory.severity + '/Sec.', '-', hotpatch]
                echo_lines.append(echo_line)

    def display(self):
        """
        Print the display lines according to the formatting parameters.
        """
        display_item = self.get_formatting_parameters_and_display_lines()
        idw, tiw, ciw, display_lines = display_item.idw, display_item.tiw, display_item.ciw, display_item.display_lines
        for display_line in sorted(
            display_lines,
            key=lambda x: (
                x[self.COLDPATCH_INDEX],
                x[self.HOTPATCH_INDEX],
                x[self.CVE_ID_INDEX],
                x[self.ADV_SEVERITY_INDEX],
            ),
        ):
            print(
                '%-*s %-*s %-*s %s'
                % (
                    idw,
                    display_line[self.CVE_ID_INDEX],
                    tiw,
                    display_line[self.ADV_SEVERITY_INDEX],
                    ciw,
                    display_line[self.COLDPATCH_INDEX],
                    display_line[self.HOTPATCH_INDEX],
                )
            )
