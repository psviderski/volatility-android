import os
from struct import pack
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
        self._config.add_option('DUMP-FILE', short_option='O', default=None,
                                help="Output file to write a dump of virtual address space to")
        self._config.add_option('DUMP-DIR', short_option='D', default = None,
                                help = "Directory to write the dump files to")

    def _parse_address(self, addr):
        if addr[:2].lower() == '0x':  # hexadecimal
            radix = 16
        elif addr[:2].lower() == '0b':  # binary
            radix = 2
        else:  # decimal
            radix = 10
        return int(addr, radix)

    def _process_name(self, dtb):
        """Returns the name of a process associated with the given dtb."""
        return "DTB_{0:#010x}".format(dtb)

    def _process_dump_filepath(self, dtb):
        dump_dir = self._config.DUMP_DIR
        if not dump_dir:
            debug.error("Dump directory is not specified.")
        process_name = self._process_name(dtb)
        dump_filepath = os.path.join(dump_dir, '{0}.bin'.format(process_name))
        if not os.path.exists(dump_filepath):
            return dump_filepath
        # The dump file path is already exist. It means that there are more
        # than one process named 'process_name'.
        name_id = 0
        while True:
            dump_filepath = os.path.join(dump_dir, '{0}_{1}.bin'.format(process_name, name_id))
            if not os.path.exists(dump_filepath):
                return dump_filepath
            name_id += 1

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
        dump_file = self._config.DUMP_FILE
        dump_dir = self._config.DUMP_DIR
        if not dump_file and not dump_dir:
            debug.error("Please specify an output file (use option --dump-file)"
                        " or a dump directory (use option --dump-dir).")
        if dump_dir and not os.path.isdir(dump_dir):
            debug.error("'{0}' is not a directory.".format(self._config.DUMP_DIR))
        self.table_header(outfd, [("DTB", "[addrpad]"),
                                  ("Start", "[addrpad]"),
                                  ("End", "[addrpad]")])
        vaddr_start = None
        vaddr_end = None
        cur_process_dtb = None
        # Dump all processes to a single file (DUMP_FILE) if DUMP_DIR is not specified.
        dump_fd = open(dump_file, 'wb') if not dump_dir else None
        index_fd = IndexFile('{0}.index'.format(dump_file)) if not dump_dir else None
        for process_dtb, vaddr, page in data:
            if process_dtb != cur_process_dtb:
                # Write the last range of virtual addresses of the previous process
                if vaddr_start is not None:
                    self.table_row(outfd, cur_process_dtb, vaddr_start, vaddr_end)
                    index_fd.write_range(vaddr_start, vaddr_end)
                vaddr_start = None
                vaddr_end = None
                cur_process_dtb = process_dtb
                if dump_dir:
                    # Close the current dump file and open a new one for the
                    # next process.
                    if dump_fd:
                        dump_fd.close()
                        index_fd.close()
                    dump_file = os.path.join(self._process_dump_filepath(process_dtb))
                    index_file = '{0}.index'.format(dump_file)
                    dump_fd = open(dump_file, 'wb')
                    index_fd = IndexFile(index_file)
            if vaddr == vaddr_end:
                vaddr_end += len(page)
            else:
                if vaddr_start is not None:
                    self.table_row(outfd, process_dtb, vaddr_start, vaddr_end)
                    index_fd.write_range(vaddr_start, vaddr_end)
                vaddr_start = vaddr
                vaddr_end = vaddr + len(page)
            dump_fd.write(page)
        # Write the last range of virtual addresses
        if vaddr_start is not None:
            self.table_row(outfd, process_dtb, vaddr_start, vaddr_end)
            index_fd.write_range(vaddr_start, vaddr_end)
        if dump_fd:
            dump_fd.close()
            index_fd.close()


class IndexFile(object):
    """Used to describe virtual address ranges that are stored in a dump file."""
    def __init__(self, filepath):
        self.fd = open(filepath, 'wb')
        self.offset = 0

    def write_range(self, vaddr_start, vaddr_end):
        """Appends index record.

        A record is a packed structure (12 bytes):
            0x0: virtual address start
            0x4: virtual address end
            0x8: offset of the range within a dump file

        """
        self.fd.write(pack('III', vaddr_start, vaddr_end, self.offset))
        self.offset += vaddr_end - vaddr_start

    def close(self):
        self.fd.close()