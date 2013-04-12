from volatility import obj, utils
from volatility.plugins.linux import auto as linux_auto


class linux_auto_dtblist(linux_auto.AbstractLinuxAutoCommand):
    """Looks for potential Directory Table Bases (DTBs)"""

    def calculate(self):
        phys_as = utils.load_as(self._config, astype='physical')
        for dtb in obj.VolMagic(phys_as).DTB.get_suggestions():
            yield dtb

    def render_text(self, outfd, data):
        self.table_header(outfd, [("DTB", "[addrpad]")])
        for dtb in data:
            self.table_row(outfd, dtb)