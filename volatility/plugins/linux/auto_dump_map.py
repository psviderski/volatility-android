import os
from volatility import debug, utils
from volatility.plugins.linux.auto_dtblist import linux_auto_dtblist


class linux_auto_dump_map(linux_auto_dtblist):
    """Dumps virtual address space of a process to disk"""

    def __init__(self, config, *args, **kwargs):
        super(linux_auto_dump_map, self).__init__(config, *args, **kwargs)
        self._config.add_option('PROC-DTB', default=None,
                                help="Dump only these Process DTBs (comma-separated physical addresses)")
        self._config.add_option('VA-START', short_option='s', type='int', default = None,
                                help = "Starting virtual address to dump")
        self._config.add_option('VA-END', short_option='e', type='int', default = None,
                                help = "Ending virtual address to dump")
        self._config.add_option('OUTPUTFILE', short_option='O', default=None,
                                help="Output file to write a dump of virtual address space to")
        self._config.add_option('DUMP-DIR', short_option='D', default = None,
                                help = "Directory to write the output files to")

    def _parse_address(self, addr):
        if addr[:2].lower() == '0x':  # hexadecimal
            radix = 16
        elif addr[:2].lower() == '0b':  # binary
            radix = 2
        else:  # decimal
            radix = 10
        return int(addr, radix)

    def calculate(self):
        if self._config.PROC_DTB:
            process_dtblist = []
            for dtb in self._config.PROC_DTB.split(','):
                try:
                    dtb = self._parse_address(dtb)
                except ValueError:
                    debug.error("Incorrect DTB given: '{0}'.".format(dtb))
                process_dtblist.append(dtb)
        else:
            # Use all potential DTBs
            process_dtblist = linux_auto_dtblist.calculate(self)
        va_start = self._config.VA_START if self._config.VA_START is not None else 0
        va_end = self._config.VA_END if self._config.VA_END is not None else (1 << 64)
        for process_dtb in process_dtblist:
            process_as = utils.load_as(self._config, dtb=process_dtb)
            for vaddr, size in process_as.get_available_pages():
                if vaddr + size <= va_start:
                    continue
                if vaddr >= va_end:
                    break
                page = process_as.read(vaddr, size)
                if vaddr + size > va_end:
                    cut_tail_offset = vaddr + size - va_end
                    page = page[:-cut_tail_offset]
                if vaddr < va_start:
                    cut_head_offset = va_start - vaddr
                    page = page[cut_head_offset:]
                    vaddr += cut_head_offset
                if page:
                    yield process_dtb, vaddr, page

    def render_text(self, outfd, data):
        output_file = self._config.OUTPUTFILE
        dump_dir = self._config.DUMP_DIR
        if not output_file and not dump_dir:
            debug.error("Please specify an output file (use option --outputfile)"
                        " or a dump directory (use option --dump-dir).")
        if dump_dir and not os.path.isdir(dump_dir):
            debug.error("'{0}' is not a directory.".format(self._config.DUMP_DIR))
        self.table_header(outfd, [("DTB", "[addrpad]"),
                                  ("Start", "[addrpad]"),
                                  ("End", "[addrpad]")])
        vaddr_start = None
        vaddr_end = None
        cur_process_dtb = None
        # Dump all processes to a single file (OUTPUTFILE) if DUMP_DIR is not specified.
        dump_fd = open(output_file, 'wb') if not dump_dir else None
        for process_dtb, vaddr, page in data:
            if process_dtb != cur_process_dtb:
                # Print the last range of virtual addresses of the previous process
                if vaddr_start is not None:
                    self.table_row(outfd, cur_process_dtb, vaddr_start, vaddr_end)
                vaddr_start = None
                vaddr_end = None
                cur_process_dtb = process_dtb
                if dump_dir:
                    # Close the current dump file and open a new one for the
                    # next process.
                    if dump_fd:
                        dump_fd.close()
                    output_file = os.path.join(dump_dir, "{0:#010x}".format(process_dtb))
                    dump_fd = open(output_file, 'wb')
            if vaddr == vaddr_end:
                vaddr_end += len(page)
            else:
                if vaddr_start is not None:
                    self.table_row(outfd, process_dtb, vaddr_start, vaddr_end)
                vaddr_start = vaddr
                vaddr_end = vaddr + len(page)
            dump_fd.write(page)
        # Print the last range of virtual addresses
        if vaddr_start is not None:
            self.table_row(outfd, process_dtb, vaddr_start, vaddr_end)
        if dump_fd:
            dump_fd.close()