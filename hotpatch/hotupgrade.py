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
from __future__ import print_function

from time import sleep
import dnf.base
import dnf.exceptions
import hawkey
from dnf.cli import commands
from dnf.cli.option_parser import OptionParser
# from dnf.cli.output import Output
from dnfpluginscore import _, logger

from .hot_updateinfo import HotUpdateinfoCommand
from .updateinfo_parse import HotpatchUpdateInfo
from .syscare import Syscare

EMPTY_TAG = "-"


@dnf.plugin.register_command
class HotupgradeCommand(dnf.cli.Command):
    aliases = ("hotupgrade",)
    summary = "Hot upgrade package using hot patch."
    usage = ""
    syscare = Syscare()
    hp_list = []

    @staticmethod
    def set_argparser(parser):
        parser.add_argument(
            'packages',
            nargs='*',
            help=_('Package to upgrade'),
            action=OptionParser.ParseSpecGroupFileCallback,
            metavar=_('PACKAGE'),
        )

    def configure(self):
        """Verify that conditions are met so that this command can run.
        These include that there are enabled repositories with gpg
        keys, and that this command is being run by the root user.
        """
        demands = self.cli.demands
        demands.sack_activation = True
        demands.available_repos = True
        demands.resolving = True
        demands.root_user = True

        commands._checkGPGKey(self.base, self.cli)
        if not self.opts.filenames:
            commands._checkEnabledRepo(self.base)

    def run(self):
        if self.opts.pkg_specs:
            self.hp_list = self.opts.pkg_specs
        elif self.opts.cves or self.opts.advisory:
            cve_pkgs = self.get_hotpatch_based_on_cve(self.opts.cves)
            advisory_pkgs = self.get_hotpatch_based_on_advisory(self.opts.advisory)
            self.hp_list = cve_pkgs + advisory_pkgs
        else:
            self.hp_list = self.get_hotpatch_of_all_cve()
            if self.hp_list:
                logger.info(_("Gonna apply all available hot patches: %s"), self.hp_list)

        available_hp_dict = self._get_available_hotpatches(self.hp_list)
        if not available_hp_dict:
            logger.info(_('No hot patches marked for install.'))
            return

        applied_old_patches = self._get_applied_old_patch(list(available_hp_dict.values()))
        if applied_old_patches:
            self._remove_hot_patches(applied_old_patches)
        else:
            self.syscare.save()
        success = self._install_hot_patch(list(available_hp_dict.keys()))
        if not success:
            logger.info(_("Error: Install hot patch failed, try to rollback."))
            output, status = self.syscare.restore()
            if status:
                raise dnf.exceptions.Error(_('Roll back failed.'))
            logger.info(_("Roll back succeed."))
            return
        return

    def run_transaction(self) -> None:
        """
        apply hot patches
        Returns:
            None
        """
        # syscare need a little bit time to process the installed hot patch
        sleep(0.5)
        if not self.base.transaction:
            for hp in self.hp_list:
                self._apply_hp(hp)
            return

        for ts_item in self.base.transaction:
            if ts_item.action not in dnf.transaction.FORWARD_ACTIONS:
                continue
            self._apply_hp(str(ts_item.pkg))

    def _apply_hp(self, hp_full_name):
        pkg_info = self._parse_hp_name(hp_full_name)
        hp_subname = self._get_hp_subname_for_syscare(pkg_info)
        output, status = self.syscare.apply(hp_subname)
        if status:
            logger.info(_('Apply hot patch failed: %s.'), hp_subname)
        else:
            logger.info(_('Apply hot patch succeed: %s.'), hp_subname)

    @staticmethod
    def _get_hp_subname_for_syscare(pkg_info: dict) -> str:
        """
        get hotpatch's subname for syscare command.  e.g. redis-1-1/ACC-1-1
        Args:
            pkg_info: out put of _parse_hp_name.

        Returns:
            str
        """
        hp_subname = (
            "-".join([pkg_info["target_name"], pkg_info["target_version"], pkg_info["target_release"]]) + '/' +
            "-".join([pkg_info["hp_name"], pkg_info["hp_version"], pkg_info["hp_release"]])
        )
        return hp_subname

    def _get_available_hotpatches(self, pkg_specs: list) -> dict:
        """
        check two conditions:
            1. the hot patch rpm package exists in repositories
            2. the hot patch's target package with specific version and release already installed
        Args:
            pkg_specs: full names of hot patches' rpm packages

        Returns:
            dict: key is available hot patches' full name,
                  value is hot patches' operate name. e.g. kernel-5.10.0-60.66.0.91.oe2203/ACC-1-1
        """
        hp_map = {}
        installed_packages = self.base.sack.query().installed()
        for pkg_spec in set(pkg_specs):
            query = self.base.sack.query()
            # check the package exist in repo or not
            subj = dnf.subject.Subject(pkg_spec)
            parsed_nevras = subj.get_nevra_possibilities(forms=[hawkey.FORM_NEVRA])
            if len(parsed_nevras) != 1:
                logger.info(_('Cannot parse NEVRA for package "{nevra}"').format(nevra=pkg_spec))
                continue

            parsed_nevra = parsed_nevras[0]
            available_hp = query.available().filter(
                name=parsed_nevra.name,
                version=parsed_nevra.version,
                release=parsed_nevra.release,
                arch=parsed_nevra.arch,
            )
            if not available_hp:
                logger.info(_('No match for argument: %s'), self.base.output.term.bold(pkg_spec))
                continue

            # check the hot patch's target package installed or not
            pkg_info = self._parse_hp_name(pkg_spec)
            installed_pkg = installed_packages.filter(
                name=pkg_info["target_name"], version=pkg_info["target_version"], release=pkg_info["target_release"]
            ).run()
            if not installed_pkg:
                logger.info(
                    _("The hot patch's target package is not installed: %s"), self.base.output.term.bold(pkg_spec)
                )
                continue

            if len(installed_pkg) != 1:
                logger.info(
                    _("The hot patch '%s' has multiple target packages, please check."),
                    self.base.output.term.bold(pkg_spec),
                )
                continue
            hp_subname = self._get_hp_subname_for_syscare(pkg_info)
            hp_map[pkg_spec] = hp_subname
        return hp_map

    @staticmethod
    def _get_applied_old_patch(available_hp_list: list) -> list:
        """
        get targets' applied accumulative hot patches.
        User can install and apply multiple sgl (single) hot patches because the rpm name is different,
        but for acc (accumulative) hot patch, user can only install one for a specific target binary rpm.
        Args:
            available_hp_list:  e.g. ['redis-1.0-1/ACC-1-1', 'redis-1.0-1/SGL_CVE_2022_1-1-1']

        Returns:
            list: applied hot patches.  e.g. ['redis-1.0-1/ACC-1-1']
        """
        hotpatch_set = set()
        hps_info = Syscare.list()
        for hp_info in hps_info:
            # hp_info[Name] is the middle column of syscare list. format: {target_rpm_name}/{hp_name}/{binary_file}
            # a hotpatch is mapped to a target binary rpm, and may affect multiple binary executable binary files
            # e.g. for hotpatch patch-redis-1-1-ACC-1-1.x86_64.rpm, it may provide 2 sub hotpatches in syscare list,
            # and SGL hotpatches may be installed at the same time
            #       redis-1-1/ACC-1-1/redis
            #       redis-1-1/ACC-1-1/redis-cli
            #       redis-1-1/SGL_CVE_2022_1-1-1/redis
            #       redis-1-1/SGL_CVE_2022_2-1-1/redis
            target, hp_name, binary_file = hp_info["Name"].split('/')
            hotpatch = target + '/' + hp_name
            # right now, if part of the hotpatch (for different binary file) is applied,
            # we consider the hotpatch is applied
            if hotpatch in available_hp_list and hp_info["Status"] != "NOT-APPLIED":
                logger.info(
                    _("The hotpatch '%s' already has a '%s' sub hotpatch of binary file '%s'"),
                    hotpatch,
                    hp_info["Status"],
                    binary_file,
                )
                if hotpatch not in hotpatch_set:
                    hotpatch_set.add(hotpatch)
        return list(hotpatch_set)

    def _remove_hot_patches(self, applied_old_patches: list) -> None:
        # output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna remove these hot patches: %s"), applied_old_patches)
        # remove_flag = output.userconfirm()
        # if not remove_flag:
        #    raise dnf.exceptions.Error(_('Operation aborted.'))

        self.syscare.save()
        for hp_name in applied_old_patches:
            logger.info(_("Remove hot patch %s."), hp_name)
            output, status = self.syscare.remove(hp_name)
            if status:
                logger.info(
                    _("Remove hot patch '%s' failed, roll back to original status."),
                    self.base.output.term.bold(hp_name),
                )
                output, status = self.syscare.restore()
                if status:
                    raise dnf.exceptions.Error(_('Roll back failed.'))
                raise dnf.exceptions.Error(_('Roll back succeed.'))

    @staticmethod
    def _parse_hp_name(hp_filename: str) -> dict:
        """
        parse hot patch's name, get target rpm's name, version, release and hp's name.
        Args:
            hp_filename: hot patch's name, in the format of
                'patch-{pkg_name}-{pkg_version}-{pkg_release}-{patchname}-{patch_version}-{patch_release}'
                e.g. patch-kernel-5.10.0-60.66.0.91.oe2203-ACC-1-1.x86_64
                     patch-kernel-5.10.0-60.66.0.91.oe2203-SGL_CVE_2022_1-1-1.x86_64
                pkg_name may have '-' in it, patch name cannot have '-'.
        Returns:
            dict: rpm info. {"target_name": "", "target_version": "", "target_release": "", "hp_name": "",
                             "hp_version": "", "hp_release": ""}
        """
        hp_filename_format = ("patch-{pkg_name}-{pkg_version}-{pkg_release}-{patch_name}-"
                              "{patch_version}-{patch_release}.{arch}")

        remove_suffix_filename = hp_filename.rsplit(".", 1)[0]
        splitted_hp_filename = remove_suffix_filename.split('-')
        try:
            rpm_info = {
                "target_release": splitted_hp_filename[-4],
                "target_version": splitted_hp_filename[-5],
                "target_name": "-".join(splitted_hp_filename[1:-5]),
                "hp_name": splitted_hp_filename[-3],
                "hp_version": splitted_hp_filename[-2],
                "hp_release": splitted_hp_filename[-1]
            }
        except IndexError as e:
            raise dnf.exceptions.Error(_("Parse hot patch name failed. Please insert correct hot patch name "
                                         "with the format: \n %s" % hp_filename_format))
        return rpm_info

    def _install_hot_patch(self, pkg_specs: list) -> bool:
        """
        install hot patches
        Args:
            pkg_specs: hot patches' full name

        Returns:
            bool
        """
        success = True
        for pkg_spec in pkg_specs:
            try:
                self.base.install(pkg_spec)
            except dnf.exceptions.MarkingError as e:
                logger.info(_('No match for argument: %s.'), self.base.output.term.bold(pkg_spec))
                success = False
        return success

    def get_hotpatch_based_on_cve(self, cves: list) -> list:
        """
        Get the hot patches corresponding to CVEs
        Args:
            cves: cve id list

        Returns:
            list: list of hot patches full name.  e.g.["tmp2-tss-3.1.0-3.oe2203sp1"]
        """
        updateinfo = HotpatchUpdateInfo(self.cli.base, self.cli)
        hp_list = []
        cve_hp_dict = updateinfo.get_hotpatches_from_cve(cves)
        for cve, hp in cve_hp_dict.items():
            if not hp:
                logger.info(_("The cve doesn't exist or cannot be fixed by hotpatch: %s"), cve)
                continue
            hp_list += hp
        return list(set(hp_list))

    def get_hotpatch_based_on_advisory(self, advisories: list) -> list:
        """
        Get the hot patches corresponding to advisories
        Args:
            advisories: advisory id list

        Returns:
            list: list of hot patches full name.  e.g.["tmp2-tss-3.1.0-3.oe2203sp1"]
        """
        updateinfo = HotpatchUpdateInfo(self.cli.base, self.cli)
        hp_list = []
        advisory_hp_dict = updateinfo.get_hotpatches_from_advisories(advisories)
        for hp in advisory_hp_dict.values():
            hp_list += hp
        return list(set(hp_list))

    def get_hotpatch_of_all_cve(self) -> list:
        """
        upgrade all exist cve using hot patches
        1. find all cves when init HotpatchUpdateInfo
        2. get the recommended hot patch for each cve
        3. deduplication
        Returns:
            ['patch-redis-6.2.5-1-HP2-1-1.x86_64']
        """
        updateinfo = HotpatchUpdateInfo(self.cli.base, self.cli)
        cve_list = self.get_all_cve_which_can_be_fixed_by_hotpatch()
        hp_list = []
        cve_hp_dict = updateinfo.get_hotpatches_from_cve(cve_list)
        for hp in cve_hp_dict.values():
            if not hp:
                continue
            hp_list += hp
        return list(set(hp_list))

    def get_all_cve_which_can_be_fixed_by_hotpatch(self) -> list:
        """
        get all unfixed cve which can be fixed by hotpatch
        use  command : dnf hot-updateinfo list cves
            Last metadata expiration check: 0:48:26 ago on 2023年06月01日 星期四 20时29分55秒.
            CVE-2023-3332  Low/Sec.       -   -
            CVE-2023-3331  Low/Sec.       -   -
            CVE-2023-1111  Important/Sec. -   patch-redis-6.2.5-1-ACC-1-1.x86_64
            CVE-2023-1111  Important/Sec. -   patch-redis-cli-6.2.5-1-ACC-1-1.x86_64

        Returns: list of unfixed cve. e.g.['CVE-2023-1111']
        """
        hp_hawkey = HotpatchUpdateInfo(self.cli.base, self.cli)
        hot_updateinfo = HotUpdateinfoCommand(self.cli)
        hot_updateinfo.opts = self.opts
        hot_updateinfo.hp_hawkey = hp_hawkey
        hot_updateinfo.filter_cves = None
        all_cves = hot_updateinfo.get_formatting_parameters_and_display_lines()
        cve_set = set()
        for display_line in all_cves.display_lines:
            if display_line[3] != EMPTY_TAG:
                cve_set.add(display_line[0])
        return list(cve_set)
