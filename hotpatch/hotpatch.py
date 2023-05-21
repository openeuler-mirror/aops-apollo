import dnf
from dnf.cli.output import Output
from dnfpluginscore import _, logger

from .syscare import Syscare
from .hotpatch_updateinfo import HotpatchUpdateInfo


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
            logger.info(_("%s hot patch '%s' failed, remain original status."), operate,
                        self.base.output.term.bold(target_patch))
        else:
            logger.info(_("%s hot patch '%s' succeed"), operate, self.base.output.term.bold(target_patch))
