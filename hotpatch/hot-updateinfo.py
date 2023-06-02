import dnf
from dnf.i18n import _
from dnf.cli.commands.updateinfo import UpdateInfoCommand
import hawkey
from .hotpatch_updateinfo import HotpatchUpdateInfo

@dnf.plugin.register_command
class HotUpdateinfoCommand(dnf.cli.Command):
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
        parser.add_argument('spec_action', nargs=1, choices=spec_action_cmds,
                            help=_('show updateinfo list'))
        
        with_cve_cmds = ['cve', 'cves']
        parser.add_argument('with_cve', nargs=1, choices=with_cve_cmds,
                            help=_('show cves'))

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

    def _filter_and_format_list_output(self, echo_lines: list, fixed_cve_id: set):
        """
        Only show specified cve information that have not been fixed, and format output
        """

        idw = tiw = ciw = 0
        format_lines = set()
        for echo_line in echo_lines:
            cve_id, adv_type, coldpatch, hotpatch = echo_line[0], echo_line[1], echo_line[2], echo_line[3]
            if self.filter_cves is not None and cve_id not in self.filter_cves:
                continue
            if cve_id in fixed_cve_id:
                continue
            if not isinstance(coldpatch, str):
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
        iterated_cve_id = set()
        for ((nevra), aupdated), id2type in sorted(mapping_nevra_cve.items(), key=lambda x: x[0]):
            pkg_name, pkg_evr, pkg_arch = nevra
            for cve_id, atypesev in id2type.items():
                iterated_cve_id.add(cve_id)
                label = type2label(self.updateinfo, *atypesev) 
                if cve_id not in self.hp_hawkey.hotpatch_cves or not self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                    echo_line = [cve_id, label, nevra, '-']
                    echo_lines.append(echo_line)
                    continue
                
                for hotpatch in self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                    echo_line = [cve_id, label, nevra, '-']
                    echo_lines.append(echo_line)
                    if hotpatch.src_pkg_nevre[0] != pkg_name:
                        continue
                    if hotpatch.state == self.hp_hawkey.INSTALLED:
                        # record the fixed cves
                        for cve_id in hotpatch.cves:
                            fixed_cve_id.add(cve_id)
                        echo_lines.pop()
                    elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                        echo_lines[-1][3] = hotpatch.nevra

        
        hp_cve_list = list(set(self.hp_hawkey.hotpatch_cves.keys()).difference(iterated_cve_id))
        for cve_id in hp_cve_list:
            for hotpatch in self.hp_hawkey.hotpatch_cves[cve_id].hotpatches:
                echo_line = [cve_id, hotpatch.advisory.severity + '/Sec.', '-', '-']
                if hotpatch.state == self.hp_hawkey.INSTALLED:
                    # record the fixed cves
                    fixed_cve_id.add(cve_id)
                    continue
                elif hotpatch.state == self.hp_hawkey.INSTALLABLE:
                    echo_line = [cve_id, hotpatch.advisory.severity + '/Sec.', '-', hotpatch.nevra]
                echo_lines.append(echo_line)

        self._filter_and_format_list_output(
            echo_lines, fixed_cve_id)

