from volatility import obj, utils
from volatility.plugins.linux import common as linux_common


class linux_auto_dtblist(linux_common.AbstractLinuxCommand):
    """Looks for potential Directory Table Bases (DTBs)"""

    @staticmethod
    def is_valid_profile(profile):
        """Returns True if the plugin is valid for the current profile."""
        return (linux_common.AbstractLinuxCommand.is_valid_profile(profile) and
                profile.metadata.get('auto', False))

    def calculate(self):
        phys_as = utils.load_as(self._config, astype='physical')
        for pgd_addr in obj.VolMagic(phys_as).DTB.get_suggestions():
            yield pgd_addr

    def render_text(self, outfd, data):
        self.table_header(outfd, [("DTB", "[addrpad]")])
        for dtb in data:
            self.table_row(outfd, dtb)