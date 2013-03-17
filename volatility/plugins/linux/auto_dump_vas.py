from volatility import debug, obj, utils
from volatility.plugins.linux import auto_dtblist


class linux_auto_dump_vas(auto_dtblist.linux_auto_dtblist):
    """Dumps virtual address space of a process"""

    def __init__(self, config, *args, **kwargs):
        super(linux_auto_dump_vas, self).__init__(config, *args, **kwargs)
        self._config.add_option('PROC-DTB', type='int', default=None,
                                help='Process DTB address')
        self._config.add_option('VAS-OUTPUT-FILE', default=None,
                                help='Output file to write VAS to')

    def calculate(self):
        process_dtb = self._config.PROC_DTB
        if not process_dtb:
            debug.error("Please specify the DTB address of a process (use option --proc-dtb).")
        output_file = self._config.VAS_OUTPUT_FILE
        if not output_file:
            debug.error("Please specify the output file to write VAS to (use option --vas-output-file).")
        process_as = utils.load_as(self._config, dtb=process_dtb)
        buffer_size = 0x1000
        with open(output_file, 'w') as output_fd:
            for vaddr in xrange(0xc0000000, 0xffffffff, buffer_size):
                buffer = process_as.read(vaddr, buffer_size)
                output_fd.write(buffer)
                yield vaddr

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Dump vaddr", "[addrpad]")])
        for vaddr in data:
            self.table_row(outfd, vaddr)