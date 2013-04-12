import os
from volatility.plugins.linux import auto as linux_auto
from volatility.plugins.linux.auto_ksymbol import linux_auto_ksymbol


KSYMTAB_TESTS = {
    'goldfish-3.4_fill_mem.lime': '/home/spy/Study/diploma/kernels/goldfish-3.4/ksymbols.map',
    'raspberry-pi_fill_mem.lime': '/home/spy/Study/diploma/kernels/raspberry-pi/ksymbols.map',
}


class linux_auto_tests(linux_auto.AbstractLinuxAutoCommand):
    """Unit tests for auto commands"""

    def fileid(self):
        path, filename = os.path.split(self._config.LOCATION)
        _, filedir = os.path.split(path)
        fileid = '_'.join((filedir, filename))
        return fileid

    def test_ksymtab(self):
        print "### Start test linux_auto_ksymtab"
        ksymbol_command = linux_auto_ksymbol(self._config)
        ksymtab_test_file = KSYMTAB_TESTS[self.fileid()]
        for test in open(ksymtab_test_file):
            symbol_name, symbol_vaddr = test.split()
            symbol_vaddr = int(symbol_vaddr, 16)
            try:
                assert ksymbol_command.get_symbol(symbol_name) == symbol_vaddr
                print '.',
            except:
                print "FAIL: {0}".format(symbol_name)
                raise
        print

    def calculate(self):
        print "###### Start unit tests on {0} ######".format(self.fileid())
        self.test_ksymtab()

    def render_text(self, outfd, data):
        outfd.write("Tests completed!\n")