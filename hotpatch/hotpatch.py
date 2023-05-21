import dnf
from dnf.i18n import _
from dnf.cli.commands.updateinfo import UpdateInfoCommand
from dnf.cli.output import Output
from dnfpluginscore import _, logger
import hawkey
from collections import Counter

from .syscare import Syscare
from .hotpatch_updateinfo import HotpatchUpdateInfo


class Versions:
    """
    Version number processing
    """

    separator = (".", "-")
    _connector = "&"

    def _order(self, version, separator=None):
        """
        Version of the cutting
        Args:
            version: version
            separator: separator

        Returns:

        """
        if not separator:
            separator = self._connector
        return tuple([int(v) for v in version.split(separator) if v.isdigit()])

    def lgt(self, version, compare_version):
        """
        Returns true if the size of the compared version is greater
        than that of the compared version, or false otherwise

        """
        for separator in self.separator:
            version = self._connector.join(
                [v for v in version.split(separator)])
            compare_version = self._connector.join(
                [v for v in compare_version.split(separator)]
            )
        version = self._order(version)
        compare_version = self._order(compare_version)
        return version >= compare_version


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
        output_format.add_argument("--list", dest='_spec_action', const='list',
                                   action='store_const',
                                   help=_('show list of cves'))
        output_format.add_argument('--apply', type=str, default=None, dest='apply_name', nargs=1,
                                   help=_('apply hotpatch'))
        output_format.add_argument('--remove', type=str, default=None, dest='remove_name', nargs=1,
                                   help=_('remove hotpatch'))
        output_format.add_argument('--active', type=str, default=None, dest='active_name', nargs=1,
                                   help=_('active hotpatch'))
        output_format.add_argument('--deactive', type=str, default=None, dest='deactive_name', nargs=1,
                                   help=_('deactive hotpatch'))
        output_format.add_argument('--accept', type=str, default=None, dest='accept_name', nargs=1,
                                   help=_('accept hotpatch'))

    def configure(self):
        demands = self.cli.demands
        demands.sack_activation = True
        demands.available_repos = True

        self.filter_cves = self.opts.cves if self.opts.cves else None

    def run(self):
        self.hp_hawkey = HotpatchUpdateInfo(self.cli.base, self.cli)
        if self.opts._spec_action == 'list':
            self.display()
        if self.opts.apply_name:
            self.apply_hot_patches(self.opts.apply_name)
        if self.opts.remove_name:
            self.remove_hot_patches(self.opts.remove_name)
        if self.opts.active_name:
            self.active_hot_patches(self.opts.active_name)
        if self.opts.deactive_name:
            self.deactive_hot_patches(self.opts.deactive_name)
        if self.opts.accept_name:
            self.accept_hot_patches(self.opts.accept_name)

    def get_mapping_nevra_cve(self) -> dict:
        """
        Get cve nevra mapping based on the UpdateInfoCommand of 'dnf updateinfo list cves'

        Returns:
        {
            (nevra, advisory.updated):
                cve_id: {
                    (advisory.type, advisory.severity),
                    ...
                }
            ...
        }
        """
        # configure UpdateInfoCommand with 'dnf updateinfo list cves'
        updateinfo = UpdateInfoCommand(self.cli)
        updateinfo.opts = self.opts

        updateinfo.opts.spec_action = 'list'
        updateinfo.opts.with_cve = True
        updateinfo.opts.spec = '*'
        updateinfo.opts._advisory_types = set()
        updateinfo.opts.availability = 'available'
        self.updateinfo = updateinfo

        apkg_adv_insts = updateinfo.available_apkg_adv_insts(
            updateinfo.opts.spec)

        mapping_nevra_cve = dict()
        for apkg, advisory, _ in apkg_adv_insts:
            nevra = (apkg.name, apkg.evr, apkg.arch)
            for ref in advisory.references:
                if ref.type != hawkey.REFERENCE_CVE:
                    continue
                mapping_nevra_cve.setdefault((nevra, advisory.updated), dict())[
                    ref.id] = (advisory.type, advisory.severity)

        return mapping_nevra_cve

    def _filter_and_format_list_output(self, echo_lines: list, fixed_cve_id: set, fixed_coldpatches: set):
        """
        Only show specified cve information that have not been fixed, and format output
        """

        def is_patch_fixed(coldpatch, fixed_coldpatches):
            """
            Check whether the coldpatch is fixed
            """
            for fixed_coldpatch in fixed_coldpatches:
                pkg_name, pkg_evr, _ = coldpatch
                fixed_pkg_name, fixed_pkg_evr, _ = fixed_coldpatch
                if pkg_name != fixed_pkg_name:
                    continue
                if version.lgt(fixed_pkg_evr, pkg_evr):
                    return True
            return False

        idw = tiw = ciw = 0
        format_lines = set()
        version = Versions()
        for echo_line in echo_lines:
            cve_id, adv_type, coldpatch, hotpatch = echo_line[0], echo_line[1], echo_line[2], echo_line[3]
            if self.filter_cves is not None and cve_id not in self.filter_cves:
                continue
            if cve_id in fixed_cve_id:
                continue
            if not isinstance(coldpatch, str):
                if is_patch_fixed(coldpatch, fixed_coldpatches):
                    continue
                else:
                    pkg_name, pkg_evr, pkg_arch = coldpatch
                    coldpatch = '%s-%s.%s' % (pkg_name, pkg_evr, pkg_arch)

            idw = max(idw, len(cve_id))
            tiw = max(tiw, len(adv_type))
            ciw = max(ciw, len(coldpatch))
            format_lines.add((cve_id, adv_type, coldpatch, hotpatch))
        for format_line in sorted(format_lines, key=lambda x: (x[2], x[3])):
            print('%-*s %-*s %-*s %s' %
                  (idw, format_line[0], tiw, format_line[1], ciw, format_line[2], format_line[3]))

    def display(self):
        """
        Append hotpatch information according to the output of 'dnf updateinfo list cves'

        echo lines:
            [
                [cve_id, adv_type, coldpatch, hotpatch]
            ]
        """

        def type2label(updateinfo, typ, sev):
            if typ == hawkey.ADVISORY_SECURITY:
                return updateinfo.SECURITY2LABEL.get(sev, _('Unknown/Sec.'))
            else:
                return updateinfo.TYPE2LABEL.get(typ, _('unknown'))

        mapping_nevra_cve = self.get_mapping_nevra_cve()
        echo_lines = []
        fixed_cve_id = set()
        fixed_coldpatches = set()
        iterated_cve_id = set()
        for ((nevra), aupdated), id2type in sorted(mapping_nevra_cve.items(), key=lambda x: x[0]):
            pkg_name, pkg_evr, pkg_arch = nevra
            for cve_id, atypesev in id2type.items():
                iterated_cve_id.add(cve_id)
                label = type2label(self.updateinfo, *atypesev)
                echo_line = [cve_id, label, nevra, '-']
                echo_lines.append(echo_line)
                if cve_id not in self.hp_hawkey.hotpatch_cves:
                    continue
                hotpatch = self.hp_hawkey.hotpatch_cves[cve_id].hotpatch
                if hotpatch is None or hotpatch.src_pkg_nevre[0] != pkg_name:
                    continue
                if hotpatch.state == self.hp_hawkey.INSTALLED:
                    # record the fixed cves
                    for cve_id in hotpatch.cves:
                        fixed_cve_id.add(cve_id)
                    # record the fixed coldpatch to filter the cves of the corresponding coldpatch with the lower version
                    fixed_coldpatches.add((nevra))
                    echo_lines.pop()
                elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                    echo_lines[-1][3] = hotpatch.nevra

        hp_cve_list = list(set(self.hp_hawkey.hotpatch_cves.keys()).difference(iterated_cve_id))
        for cve_id in hp_cve_list:
            hotpatch = self.hp_hawkey.hotpatch_cves[cve_id].hotpatch
            if hotpatch is None:
                continue
            echo_line = [cve_id, hotpatch.advisory.severity + '/Sec.', '-', '-']
            if hotpatch.state == self.hp_hawkey.INSTALLED:
                continue
            elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                echo_line = [cve_id, hotpatch.advisory.severity + '/Sec.', '-', hotpatch.nevra]
            echo_lines.append(echo_line)

        self._filter_and_format_list_output(
            echo_lines, fixed_cve_id, fixed_coldpatches)

    def remove_hot_patches(self, target_patch: list) -> None:
        """
        remove hotpatch using syscare command
        Args:
            target_patch: type:list,e.g.:['redis-6.2.5-1/HP2']

        Returns:
            None
        """
        if len(target_patch) != 1:
            logger.error("using command dnf hotpatch --remove wrong! ")
            return
        target_patch = target_patch[0]
        output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna remove this hot patche: %s"), self.base.output.term.bold(target_patch))

        output, status = self.syscare.remove(target_patch)
        if status:
            logger.info(_("Remove hot patch '%s' failed, remain original status."),
                        self.base.output.term.bold(target_patch))
        else:
            logger.info(_("Remove hot patch '%s' succeed"), self.base.output.term.bold(target_patch))
        return

    def active_hot_patches(self, target_patch: list) -> None:
        """
        activate hotpatch using syscare command
        Args:
            target_patch: type:list,e.g.:['redis-6.2.5-1/HP2']

        Returns:
            None
        """
        if len(target_patch) != 1:
            logger.error("using dnf hotpatch --active wrong!")
            return
        target_patch = target_patch[0]
        output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna activate this hot patch: %s"), self.base.output.term.bold(target_patch))

        output, status = self.syscare.active(target_patch)
        if status:
            logger.info(_("activate hot patch '%s' failed, remain original status."),
                        self.base.output.term.bold(target_patch))
        else:
            logger.info(_("activate hot patch '%s' succeed"), self.base.output.term.bold(target_patch))
        return

    def deactive_hot_patches(self, target_patch: list) -> None:
        """
        deactive hotpatch using syscare command
        Args:
            target_patch: type:list,e.g.:['redis-6.2.5-1/HP2']

        Returns:
            None
        """
        if len(target_patch) != 1:
            logger.error("using dnf hotpatch --deactive wrong!")
            return
        target_patch = target_patch[0]
        output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna deactivate this hot patch: %s"), self.base.output.term.bold(target_patch))

        output, status = self.syscare.deactive(target_patch)
        if status:
            logger.info(_("deactivate hot patch '%s' failed, remain original status."),
                        self.base.output.term.bold(target_patch))
        else:
            logger.info(_("deactivate hot patch '%s' succeed"), self.base.output.term.bold(target_patch))
        return

    def apply_hot_patches(self, target_patch: list) -> None:
        """
         apply hotpatch using syscare command
         Args:
             target_patch: type:list,e.g.:['redis-6.2.5-1/HP2']

         Returns:
             None
         """
        if len(target_patch) != 1:
            logger.error("using dnf hotpatch --apply wrong!")
            return
        target_patch = target_patch[0]
        output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna apply this hot patch: %s"), self.base.output.term.bold(target_patch))

        output, status = self.syscare.apply(target_patch)
        if status:
            logger.info(_("apply hot patch '%s' failed, remain original status."),
                        self.base.output.term.bold(target_patch))
        else:
            logger.info(_("apply hot patch '%s' succeed"), self.base.output.term.bold(target_patch))
        return

    def accept_hot_patches(self, target_patch: list) -> None:
        """
         accept hotpatch using syscare command
         Args:
             target_patch: type:list,e.g.:['redis-6.2.5-1/HP2']

         Returns:
             None
         """
        if len(target_patch) != 1:
            logger.error("using dnf hotpatch --accept wrong!")
            return
        target_patch = target_patch[0]
        output = Output(self.base, dnf.conf.Conf())
        logger.info(_("Gonna accept this hot patch: %s"), self.base.output.term.bold(target_patch))

        output, status = self.syscare.accept(target_patch)
        if status:
            logger.info(_("accept hot patch '%s' failed, remain original status."),
                        self.base.output.term.bold(target_patch))
        else:
            logger.info(_("accept hot patch '%s' succeed"), self.base.output.term.bold(target_patch))
        return
