from volatility import debug, obj, utils
from volatility.plugins.linux import auto_dtblist


class linux_auto_dump_map(auto_dtblist.linux_auto_dtblist):
    """Dumps virtual address space of a process to disk"""

    def __init__(self, config, *args, **kwargs):
        super(linux_auto_dump_map, self).__init__(config, *args, **kwargs)
        self._config.add_option('PROC-DTB', type='int', default=None,
                                help="Process DTB address")
        self._config.add_option('OUTPUTFILE', short_option='O', default=None,
                                help="Output file to write a dump of virtual address space to")
        self._config.add_option('DUMP-DIR', short_option='D', default = None,
                                help = "Directory to write the output files to")

    def calculate(self):
        process_dtb = self._config.PROC_DTB
        if not process_dtb:
            debug.error("Please specify a DTB address of a process (use option --proc-dtb).")
        process_as = utils.load_as(self._config, dtb=process_dtb)
        for vaddr, size in process_as.get_available_pages():
            page = process_as.read(vaddr, size)
            if page:
                yield vaddr, page

    def render_text(self, outfd, data):
        output_file = self._config.OUTPUTFILE
        if not output_file:
            debug.error("Please specify an output file (use option --outputfile).")
        self.table_header(outfd, [("Start", "[addrpad]"),
                                  ("End", "[addrpad]")])
        with open(output_file, 'wb') as output_fd:
            vaddr_start = None
            vaddr_end = None
            for vaddr, page in data:
                if vaddr == vaddr_end:
                    vaddr_end += len(page)
                else:
                    if vaddr_start is not None:
                        self.table_row(outfd, vaddr_start, vaddr_end)
                    vaddr_start = vaddr
                    vaddr_end = vaddr + len(page)
                output_fd.write(page)
            # Print the last range of virtual addresses
            if vaddr_start is not None:
                self.table_row(outfd, vaddr_start, vaddr_end)