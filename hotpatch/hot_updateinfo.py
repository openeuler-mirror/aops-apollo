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
from .baseclass import Hotpatch


@dataclass
class DisplayItem:
    """
    Class for storing the formatting parameters and display lines.

    idw(int): the width of 'cve_id'
    tiw(int): the width of 'adv_type'
    ciw(int): the width of 'coldpatch'
    display_lines(set): {
            (cve_id, adv_type, coldpatch, hotpatch),
        }
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

        availability = parser.add_mutually_exclusive_group()
        availability.add_argument(
            "--available",
            dest="availability",
            const='available',
            action='store_const',
            help=_("cves about newer versions of installed packages (default)"),
        )
        availability.add_argument(
            "--installed",
            dest="availability",
            const='installed',
            action='store_const',
            help=_("cves about equal and older versions of installed packages"),
        )

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
        Get cve nevra mapping based on the UpdateInfoCommand of 'dnf updateinfo list cves'.

        Returns:
            dict: to collect cve and cold patch updateinfo information
            {
                (name-version-release.arch, advisory.updated): {
                    cve_id: (advisory.type, advisory.severity)
                }
            }
        """

        apkg_adv_insts = self.get_apkg_adv_insts()

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

    def get_apkg_adv_insts(self):
        """
        Configure UpdateInfoCommand with 'dnf updateinfo list cves --available' (default) or
        'dnf updateinfo list cves --installed' according to the args, and get available package, advisory
        and package installation information.

        Returns:
            generator: generator for (available package, advisory, package installation
                       information)
        """
        updateinfo = UpdateInfoCommand(self.cli)
        updateinfo.opts = self.opts

        updateinfo.opts.spec_action = 'list'
        updateinfo.opts.with_cve = True
        updateinfo.opts.spec = '*'
        updateinfo.opts._advisory_types = set()
        updateinfo.opts.availability = self.opts.availability
        self.updateinfo = updateinfo

        if self.updateinfo.opts.availability == 'installed':
            apkg_adv_insts = updateinfo.installed_apkg_adv_insts(updateinfo.opts.spec)
        else:
            apkg_adv_insts = updateinfo.available_apkg_adv_insts(updateinfo.opts.spec)

        return apkg_adv_insts

    def get_fixed_cve_id_and_hotpatch_require_info(self, fixed_cve_id_and_hotpatch: set):
        """
        Get fixed cve id and hotpatch require package information.

        Args:
            fixed_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }

        Returns:
            set:
            e.g.
            {
                ('CVE-2023-1111', 'redis-6.2.5-1')
                ('CVE-2023-1112', 'redis-6.2.5-1,redis-cli-6.2.5-1')
            }
        """
        fixed_cve_id_and_hotpatch_require_info = set()
        for fixed_cve_id, fixed_hotpatch in fixed_cve_id_and_hotpatch:
            fixed_cve_id_and_hotpatch_require_info.add((fixed_cve_id, fixed_hotpatch.required_pkgs_str))
        return fixed_cve_id_and_hotpatch_require_info

    def get_iterated_cve_id_and_hotpatch_require_info(self, iterated_cve_id_and_hotpatch: set):
        """
        Get iterated cve id and hotpatch require package name information.

        Args:
            iterated_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }


        Returns:
            set
            e.g.
            {
                ('CVE-2023-1111', 'redis')
                ('CVE-2023-1112', 'redis,redis-cli')
            }
        """
        iterated_cve_id_and_hotpatch_require_info = set()
        for iterated_cve_id, iterated_hotpatch in iterated_cve_id_and_hotpatch:
            iterated_cve_id_and_hotpatch_require_info.add((iterated_cve_id, iterated_hotpatch.required_pkgs_name_str))
        return iterated_cve_id_and_hotpatch_require_info

    def check_is_in_fixed_cve_id_and_hotpatch_require_info(
        self, cve_id: str, hotpatch: Hotpatch, fixed_cve_id_and_hotpatch_require_info: set
    ):
        """
        Check the (cve_id, hotpatch.required_pkgs_str) whether is in fixed_cve_id_and_hotpatch_require_info.
        If the (cve_id, hotpatch.required_pkgs_str) is in fixed_cve_id_and_hotpatch_require_info, the cve corresponding
        to the hotpatch should be fixed.

        Args:
            cve_id(str)
            hotpatch(Hotpatch)
            fixed_cve_id_and_hotpatch_require_info(set):
            e.g.
            {
                ('CVE-2023-1111', 'redis-6.2.5-1')
                ('CVE-2023-1112', 'redis-6.2.5-1')
            }

        Returns:
            bool: whether the cve corresponding to the hotpatch is fixed
        """
        is_fixed = False
        if (cve_id, hotpatch.required_pkgs_str) in fixed_cve_id_and_hotpatch_require_info:
            is_fixed = True
        return is_fixed

    def check_is_in_iterated_cve_id_and_hotpatch_require_info(
        self, cve_id: str, hotpatch: Hotpatch, iterated_cve_id_and_hotpatch_require_info: set
    ):
        """
        Check the (cve_id, hotpatch.required_pkgs_name_str) whether is in iterated_cve_id_and_hotpatch_require_info.
        If the (cve_id, hotpatch.required_pkgs_name_str) is in fixed_cve_id_and_hotpatch_require_info, the cve
        corresponding to the hotpatch should be iterated.

        Args:
            cve_id(str)
            hotpatch(Hotpatch)
            iterated_cve_id_and_hotpatch_require_info(set):
            e.g.
            {
                ('CVE-2023-1111', 'redis')
                ('CVE-2023-1112', 'redis')
            }

        Returns:
            bool: whether the cve corresponding to the hotpatch is iterated
        """
        is_iterated = False
        if (
            hotpatch.state in (self.hp_hawkey.UNINSTALLABLE, self.hp_hawkey.UNRELATED)
            and (cve_id, hotpatch.required_pkgs_name_str) in iterated_cve_id_and_hotpatch_require_info
        ):
            is_iterated = True
        return is_iterated

    def get_filtered_display_item(
        self,
        format_lines: set,
        fixed_cve_id_and_hotpatch: set,
        installable_cve_id_and_hotpatch: set,
        iterated_cve_id_and_hotpatch: set,
    ):
        """
        Get filtered display item.

        Args:
            format_lines(set):
            {
                (cve_id, adv_type, coldpatch, hotpatch)
            }

            fixed_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }

            iterated_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }

        Returns:
            DisplayItem: for display
        """
        if self.updateinfo.opts.availability == 'installed':
            display_item = self.get_installed_filtered_display_item(
                format_lines, fixed_cve_id_and_hotpatch, installable_cve_id_and_hotpatch
            )
            return display_item
        display_item = self.get_available_filtered_display_item(
            format_lines, fixed_cve_id_and_hotpatch, iterated_cve_id_and_hotpatch
        )
        return display_item

    def get_installed_filtered_display_item(
        self, format_lines: set, fixed_cve_id_and_hotpatch: set, installable_cve_id_and_hotpatch: set
    ):
        """
        Get filtered display item by removing installable cve id and hotpatch, and removing iterated cve id
        and hotpatch. For hotpatch, only show ones which have been installed and been actived/accepted in
        syscare.

        Args:
            format_lines(set):
            {
                (cve_id, adv_type, coldpatch, hotpatch)
            }

            installable_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }

        Returns:
            DisplayItem: for display

        """
        display_lines = set()

        # calculate the width of each column
        idw = tiw = ciw = 0
        for format_line in format_lines:
            cve_id, adv_type, coldpatch, hotpatch = (
                format_line[self.CVE_ID_INDEX],
                format_line[self.ADV_SEVERITY_INDEX],
                format_line[self.COLDPATCH_INDEX],
                format_line[self.HOTPATCH_INDEX],
            )
            if self.filter_cves is not None and cve_id not in self.filter_cves:
                continue
            if (cve_id, hotpatch) in installable_cve_id_and_hotpatch:
                if coldpatch == '-':
                    continue
                else:
                    hotpatch = '-'

            if isinstance(hotpatch, Hotpatch):
                if (cve_id, hotpatch) in fixed_cve_id_and_hotpatch or hotpatch.state == self.hp_hawkey.INSTALLED:
                    hotpatch = hotpatch.nevra
                elif hotpatch.state in (self.hp_hawkey.UNINSTALLABLE, self.hp_hawkey.UNRELATED):
                    hotpatch = '-'

            if coldpatch == '-' and hotpatch == '-':
                continue

            idw = max(idw, len(cve_id))
            tiw = max(tiw, len(adv_type))
            ciw = max(ciw, len(coldpatch))
            display_lines.add((cve_id, adv_type, coldpatch, hotpatch))

        display_item = DisplayItem(idw=idw, tiw=tiw, ciw=ciw, display_lines=display_lines)
        return display_item

    def get_available_filtered_display_item(
        self, format_lines: set, fixed_cve_id_and_hotpatch: set, iterated_cve_id_and_hotpatch: set
    ):
        """
        Get filtered display item by removing fixed cve id and hotpatch, and removing iterated cve id
        and hotpatch.

        Args:
            format_lines(set):
            {
                (cve_id, adv_type, coldpatch, hotpatch)
            }

            fixed_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }

            iterated_cve_id_and_hotpatch(set):
            e.g.
            {
                ('CVE-2023-1111', Hotpatch)
            }

        Returns:
            DisplayItem: for display
        """
        display_lines = set()

        fixed_cve_id_and_hotpatch_require_info = self.get_fixed_cve_id_and_hotpatch_require_info(
            fixed_cve_id_and_hotpatch
        )
        iterated_cve_id_and_hotpatch_require_info = self.get_iterated_cve_id_and_hotpatch_require_info(
            iterated_cve_id_and_hotpatch
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
            if self.filter_cves is not None and cve_id not in self.filter_cves:
                continue
            if (cve_id, hotpatch) in fixed_cve_id_and_hotpatch:
                continue

            if isinstance(hotpatch, Hotpatch):
                if self.check_is_in_iterated_cve_id_and_hotpatch_require_info(
                    cve_id, hotpatch, iterated_cve_id_and_hotpatch_require_info
                ):
                    continue
                if self.check_is_in_fixed_cve_id_and_hotpatch_require_info(
                    cve_id, hotpatch, fixed_cve_id_and_hotpatch_require_info
                ):
                    continue
                # format hotpatch
                if hotpatch.state == self.hp_hawkey.INSTALLABLE:
                    hotpatch = hotpatch.nevra
                elif hotpatch.state == self.hp_hawkey.UNINSTALLABLE:
                    hotpatch = '-'
                elif hotpatch.state == self.hp_hawkey.UNRELATED and coldpatch == '-':
                    continue
                elif hotpatch.state == self.hp_hawkey.UNRELATED:
                    hotpatch = '-'

            idw = max(idw, len(cve_id))
            tiw = max(tiw, len(adv_type))
            ciw = max(ciw, len(coldpatch))
            display_lines.add((cve_id, adv_type, coldpatch, hotpatch))

        display_item = DisplayItem(idw=idw, tiw=tiw, ciw=ciw, display_lines=display_lines)
        return display_item

    def append_fixed_cve_id_and_hotpatch(self, fixed_cve_id_and_hotpatch: set):
        """
        Append fixed cve id and hotpatch in fixed_cve_id_and_hotpatch. The ACC hotpatch that are less or equal
        to the highest ACC actived version-release for the same target required package, is considered to be
        fixed.

        Args:
           fixed_cve_id_and_hotpatch(set)
           e.g.
           {
                ('CVE-2023-2221', Hotpatch)
           }
        Returns:
            set:
            e.g.
            {
                ('CVE-2023-2221', Hotpatch),
                ('CVE-2023-1111', Hotpatch)
            }

        """
        versions = Versions()
        # {hotpatch_required_pkgs_str: version-release}
        hotpatch_vere_mapping = dict()
        for _, fixed_hotpatch in fixed_cve_id_and_hotpatch:
            # get the highest version-release for each target required package
            required_pkgs_str = fixed_hotpatch.required_pkgs_str
            current_vere = "%s-%s" % (fixed_hotpatch.version, fixed_hotpatch.release)
            if fixed_hotpatch.hotpatch_name != "ACC":
                continue
            if required_pkgs_str not in hotpatch_vere_mapping:
                hotpatch_vere_mapping[required_pkgs_str] = current_vere
            elif versions.larger_than(current_vere, hotpatch_vere_mapping[required_pkgs_str]):
                hotpatch_vere_mapping[required_pkgs_str] = current_vere

        # get all hot hotpatches that are less or equal to the highest version-release, and record the cves
        # which they fix
        for required_pkgs_str, actived_vere in hotpatch_vere_mapping.items():
            all_hotpatches = self.hp_hawkey._hotpatch_required_pkg_info_str[required_pkgs_str]
            for cmped_vere, hotpatch in all_hotpatches:
                if hotpatch.hotpatch_name != "ACC":
                    continue
                if not versions.larger_than(actived_vere, cmped_vere):
                    continue
                for cve_id in hotpatch.cves:
                    fixed_cve_id_and_hotpatch.add((cve_id, hotpatch))
        return fixed_cve_id_and_hotpatch

    def get_formatting_parameters_and_display_lines(self):
        """
        Append hotpatch information according to the output of 'dnf updateinfo list cves'

        Returns:
            DisplayItem: for display
        """

        def type2label(updateinfo, typ, sev):
            if typ == hawkey.ADVISORY_SECURITY:
                return updateinfo.SECURITY2LABEL.get(sev, _('Unknown/Sec.'))
            else:
                return updateinfo.TYPE2LABEL.get(typ, _('unknown'))

        mapping_nevra_cve = self.get_mapping_nevra_cve()
        echo_lines = set()
        fixed_cve_id_and_hotpatch = set()
        installable_cve_id_and_hotpatch = set()
        uninstallable_cve_id_and_hotpatch = set()
        iterated_cve_id_and_hotpatch = set()

        for ((nevra), aupdated), id2type in sorted(mapping_nevra_cve.items(), key=lambda x: x[0]):
            pkg_name, pkg_evr, pkg_arch = nevra
            coldpatch = '%s-%s.%s' % (pkg_name, pkg_evr, pkg_arch)
            for cve_id, atypesev in id2type.items():
                label = type2label(self.updateinfo, *atypesev)
                # if there is no hotpatch corresponding to the cve id, mark hotpatch as '-'
                if cve_id not in self.hp_hawkey.hotpatch_cves or not self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                    echo_line = (cve_id, label, coldpatch, '-')
                    echo_lines.add(echo_line)
                    continue

                for hotpatch in self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                    # if cold patch name does not match with hotpatch required pkg name (target fix pkgs)
                    if pkg_name not in hotpatch._required_pkgs_info.keys():
                        echo_line = (cve_id, label, coldpatch, '-')
                        echo_lines.add(echo_line)
                        continue
                    if hotpatch.state == self.hp_hawkey.INSTALLED:
                        # record the fixed cve_id and hotpatch, filter the packages that are lower than
                        # the currently installed package for solving the same cve and target required
                        # pakcage
                        fixed_cve_id_and_hotpatch.add((cve_id, hotpatch))
                        iterated_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                        # record the installable cve_id and hotpatch, filter the packages that are bigger
                        # than the currently installed package
                        installable_cve_id_and_hotpatch.add((cve_id, hotpatch))
                        iterated_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    elif hotpatch.state == self.hp_hawkey.UNINSTALLABLE:
                        uninstallable_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    echo_line = (cve_id, label, coldpatch, hotpatch)
                    echo_lines.add(echo_line)

        self.add_untraversed_hotpatches(
            echo_lines,
            fixed_cve_id_and_hotpatch,
            installable_cve_id_and_hotpatch,
            uninstallable_cve_id_and_hotpatch,
            iterated_cve_id_and_hotpatch,
        )
        # lower version ACC hotpatch of fixed ACC hotpatch, is also considered to be fixed
        fixed_cve_id_and_hotpatch = self.append_fixed_cve_id_and_hotpatch(fixed_cve_id_and_hotpatch)
        # remove fixed cve and hotpatch from installable_cve_id_and_hotpatch
        installable_cve_id_and_hotpatch = installable_cve_id_and_hotpatch.difference(fixed_cve_id_and_hotpatch)
        display_item = self.get_filtered_display_item(
            echo_lines, fixed_cve_id_and_hotpatch, installable_cve_id_and_hotpatch, iterated_cve_id_and_hotpatch
        )

        return display_item

    def add_untraversed_hotpatches(
        self,
        echo_lines: set,
        fixed_cve_id_and_hotpatch: set,
        installable_cve_id_and_hotpatch: set,
        uninstallable_cve_id_and_hotpatch: set,
        iterated_cve_id_and_hotpatch: set,
    ):
        """
        Add the echo lines, which are only with hotpatch but no coldpatch. And append
        fixed_cve_id_and_hotpatch and iterated_cve_id_and_hotpatch.

        Args:
            echo_lines(set)
            fixed_cve_id_and_hotpatch(set)
            installable_cve_id_and_hotpatch(set)
            uninstallable_cve_id_and_hotpatch(set)
            iterated_cve_id_and_hotpatch(set)
        """
        for cve_id, cve in self.hp_hawkey.hotpatch_cves.items():
            for hotpatch in cve.hotpatches:
                if hotpatch.state == self.hp_hawkey.UNRELATED:
                    continue
                if (cve_id, hotpatch) in iterated_cve_id_and_hotpatch:
                    continue
                if (cve_id, hotpatch) in uninstallable_cve_id_and_hotpatch:
                    continue
                if hotpatch.state == self.hp_hawkey.INSTALLED:
                    fixed_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    iterated_cve_id_and_hotpatch.add((cve_id, hotpatch))
                elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                    installable_cve_id_and_hotpatch.add((cve_id, hotpatch))
                    iterated_cve_id_and_hotpatch.add((cve_id, hotpatch))
                echo_line = (cve_id, hotpatch.advisory.severity + '/Sec.', '-', hotpatch)
                echo_lines.add(echo_line)

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
