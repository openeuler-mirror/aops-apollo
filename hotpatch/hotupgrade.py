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

import hawkey
import dnf.base
import dnf.exceptions
from dnf.cli import commands
from dnf.cli.option_parser import OptionParser
from dnf.cli.output import Output
from dnfpluginscore import _, logger

from .syscare import Syscare
from .hotpatch_updateinfo import HotpatchUpdateInfo
from .hot_updateinfo import HotUpdateinfoCommand

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
        parser.add_argument('packages', nargs='*', help=_('Package to upgrade'),
                            action=OptionParser.ParseSpecGroupFileCallback,
                            metavar=_('PACKAGE'))

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
            self.hp_list = self.upgrade_all()
            logger.info(_("Gonna apply these hot patches:%s"), self.hp_list)

        hp_target_map = self._get_available_hotpatches(self.hp_list)
        if not hp_target_map:
            raise dnf.exceptions.Error(_('No hot patches marked for install.'))

        target_patch_map = self._get_applied_old_patch(list(hp_target_map.values()))
        if target_patch_map:
            self._remove_hot_patches(target_patch_map)
        else:
            self.syscare.save()
        success = self._install_hot_patch(list(hp_target_map.keys()))
        if not success:
            output, status = self.syscare.restore()
            if status:
                raise dnf.exceptions.Error(_('Roll back failed.'))
            raise dnf.exceptions.Error(_("Roll back succeed."))
        return

    def run_transaction(self) -> None:
        """
        apply hot patches
        Returns:
            None
        """
        logger.info(_('Applying hot patch'))
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
        hp_full_name = "-".join([pkg_info["name"], pkg_info["version"], pkg_info["release"]]) \
                       + '/' + pkg_info["hp_name"]
        output, status = self.syscare.apply(hp_full_name)
        if status:
            logger.info(_('Apply hot patch failed: %s.'), hp_full_name)
        else:
            logger.info(_('Apply hot patch succeed: %s.'), hp_full_name)

    def _get_available_hotpatches(self, pkg_specs: list) -> dict:
        """
        check two conditions:
            1. the hot patch rpm package exists in repositories
            2. the hot patch's target package with specific version and release already installed
        Args:
            pkg_specs: full names of hot patches' rpm packages

        Returns:
            dict: key is available hot patches' full name, value is target package's name-version-release
        """
        hp_target_map = {}
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
            available_hp = query.available().filter(name=parsed_nevra.name, version=parsed_nevra.version,
                                                    release=parsed_nevra.release, arch=parsed_nevra.arch)
            if not available_hp:
                logger.info(_('No match for argument: %s'), self.base.output.term.bold(pkg_spec))
                continue

            # check the hot patch's target package installed or not
            pkg_info = self._parse_hp_name(pkg_spec)
            installed_pkg = installed_packages.filter(name=pkg_info["name"],
                                                      version=pkg_info["version"],
                                                      release=pkg_info["release"]).run()
            if not installed_pkg:
                logger.info(_("The hot patch's target package is not installed: %s"),
                            self.base.output.term.bold(pkg_spec))
                continue

            if len(installed_pkg) != 1:
                logger.info(_("The hot patch '%s' has multiple target packages, please check."),
                            self.base.output.term.bold(pkg_spec))
                continue
            target = "-".join([pkg_info["name"], pkg_info["version"], pkg_info["release"]])
            hp_target_map[pkg_spec] = target
        return hp_target_map

    def _get_applied_old_patch(self, targets: list):
        """
        get targets' applied hot patches
        Args:
            targets: target RPMs' name-version-release.  e.g. redis-1.0-1

        Returns:
            dict: targets' applied hot patches.  e.g. {'redis-1.0-1': 'redis-1.0-1/HP001'}
        """
        target_patch_map = {}
        hps_info = Syscare.list()
        for hp_info in hps_info:
            target, hp_name = hp_info["Name"].split('/')
            if target in targets and hp_info["Status"] != "NOT-APPLIED":
                logger.info(_("The target package '%s' has a hotpatch '%s' applied"),
                            self.base.output.term.bold(target),
                            self.base.output.term.bold(hp_name))
                target_patch_map[target] = hp_info["Name"]
        return target_patch_map

    def _remove_hot_patches(self, target_patch_map: dict) -> None:
        output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna remove these hot patches: %s"), list(target_patch_map.values()))
        # remove_flag = output.userconfirm()
        # if not remove_flag:
        #    raise dnf.exceptions.Error(_('Operation aborted.'))

        self.syscare.save()
        for target, hp_name in target_patch_map.items():
            logger.info(_("Remove hot patch %s."), hp_name)
            output, status = self.syscare.remove(hp_name)
            if status:
                logger.info(_("Remove hot patch '%s' failed, roll back to original status."),
                            self.base.output.term.bold(hp_name))
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
                'patch-{pkg_name}-{pkg_version}-{pkg_release}-{patchname}-{patch_version}-{patch_release}.rpm'
                e.g. patch-kernel-5.10.0-60.66.0.91.oe2203-HP001-1-1.x86_64.rpm
                pkg_name may have '-' in it, patch name cannot have '-'.
        Returns:
            dict: rpm info. {"name": "", "version": "", "release": "", "hp_name": ""}
        """
        splitted_hp_filename = hp_filename.split('-')
        try:
            rpm_info = {"release": splitted_hp_filename[-4], "version": splitted_hp_filename[-5],
                        "name": "-".join(splitted_hp_filename[1:-5]), "hp_name": splitted_hp_filename[-3]}
        except IndexError as e:
            raise dnf.exceptions.Error(_('Parse hot patch name failed. Please insert correct hot patch name.'))
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
                logger.info(_('No match for argument: %s.'),
                            self.base.output.term.bold(pkg_spec))
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
                logger.info(_("The cve's hot patch doesn't exist: %s"), cve)
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

    def get_hot_updateinfo_list(self):
        """
        Find all hotpatches and upgrade all
        use  command : dnf hot-updateinfo list cves
        Last metadata expiration check: 0:48:26 ago on 2023年06月01日 星期四 20时29分55秒.
        CVE-2023-3332  Low/Sec.       -   -
        CVE-2023-3331  Low/Sec.       -   -
        CVE-2023-1112  Important/Sec. -   patch-redis-6.2.5-1-HP001-1-1.x86_64
        CVE-2023-1111  Important/Sec. -   patch-redis-6.2.5-1-HP001-1-1.x86_64

        return:list e.g.
        ['patch-redis-6.2.5-1-HP002-1-1.x86_64', '-', '-']

        """
        hp_hawkey = HotpatchUpdateInfo(self.cli.base, self.cli)
        hot_updateinfo = HotUpdateinfoCommand(self.cli)
        hot_updateinfo.opts = self.opts
        hot_updateinfo.hp_hawkey = hp_hawkey
        hot_updateinfo.filter_cves = None
        all_cves = hot_updateinfo.get_formatting_parameters_and_display_lines()
        result = list()
        for display_line in all_cves.display_lines:
            result.append(display_line[3])
        return result

    def upgrade_all(self):
        """
        upgrade all exist cve and hot patches

        Return:
             find all patches and return patches list
            e.g.:
            ['patch-redis-6.2.5-1-HP2-1-1.x86_64']
        """
        hotpatchs_info = self.get_hot_updateinfo_list()
        hp_list = list()
        for item in hotpatchs_info:
            if item != EMPTY_TAG:
                hp_list.append(item)
        if len(hp_list) == 0 or len(hp_list) == 1:
            return hp_list

        hp_list.sort(reverse=True)
        res_hp_list = list()
        res_hp_list.append(hp_list[0])
        pkg_name = hp_list[0].split("-")[1]
        for hp in hp_list[1:]:
            pkg_name_tmp = hp.split("-")[1]
            if pkg_name_tmp == pkg_name:
                continue
            else:
                res_hp_list.append(hp)
                pkg_name = hp.split("-")[1]
        return res_hp_list
