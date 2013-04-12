import re
from struct import pack, unpack
from volatility import debug, obj, utils
from volatility.plugins.linux import auto as linux_auto


KSYMTAB_MAX_SIZE = 0x40000  # sum of the maximum sizes of all ksymtab sections


class linux_auto_ksymbol(linux_auto.AbstractLinuxAutoCommand):
    """Extracts a kernel symbol from a __ksymtab section."""

    def __init__(self, config, *args, **kwargs):
        linux_auto.AbstractLinuxAutoCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('KSYMBOL', short_option='K', default=None,
                                help="Kernel symbol name to extract")
        self.kernel_image = None
        self.ksymtab_initialized = False
        self.ksymtab_strings_offset = 0
        self.page_offset = 0xc0000000

    def _init_ksymtab(self):
        phys_as = utils.load_as(self._config, astype='physical')
        start_addr, _ = phys_as.get_available_addresses().next()
        # First 16 MB of physical memory
        self.kernel_image = phys_as.read(start_addr, 0x1000000)
        # Init page_offset
        if phys_as.profile.metadata.get('memory_model', '32bit') != '32bit':
            raise NotImplementedError
        self.ksymtab_initialized = True
        # Locate the physical offset of the ksymtab_strings section
        for match in re.finditer('init_task\0', self.kernel_image):
            offset = match.start()
            if re.match(r'[0-9a-z_]', self.kernel_image[offset - 1:offset]):
                # 'init_task' is a substring of another symbol like 'xxx_init_task'
                continue
            # TODO: Choose the right one, not the first. Find the beginning
            # of the ksymtab_strings section
            debug.debug("Found the physical offset of the ksymtab_strings "
                        "section: {0:#010x}".format(offset))
            self.ksymtab_strings_offset = offset
            return
        debug.warning("Can't locate a ksymtab_strings section")

    def get_symbol(self, name):
        """Gets a symbol address by its name."""
        if not self.ksymtab_initialized:
            self._init_ksymtab()
        for match in re.finditer('{0}\0'.format(name), self.kernel_image[self.ksymtab_strings_offset:]):
            symbol_str_offset = self.ksymtab_strings_offset + match.start()
            if re.match(r'[0-9a-z_]', self.kernel_image[symbol_str_offset - 1:symbol_str_offset]):
                # Symbol string is a substring of another symbol string,
                # e.g. 'use_mm' is a substring of 'unuse_mm'.
                continue
            debug.debug("Found the physical offset of the symbol string "
                        "'{0}': {1:#010x}".format(name, symbol_str_offset))
            symbol_str_vaddr = symbol_str_offset + self.page_offset
            symbol_str_vaddr_little = pack('<L', symbol_str_vaddr)
            ksymtab_offset = max(0, symbol_str_offset - KSYMTAB_MAX_SIZE) >> 2 << 2  # align to x4
            ksymtab_data = self.kernel_image[ksymtab_offset:ksymtab_offset + KSYMTAB_MAX_SIZE]
            for match in re.finditer(symbol_str_vaddr_little.encode('hex'), ksymtab_data.encode('hex')):
                ksymtab_entry_offset = ksymtab_offset + match.start() / 2 - 4
                symbol_vaddr, = unpack('<L', self.kernel_image[ksymtab_entry_offset:ksymtab_entry_offset + 4])
                debug.debug("Requested kernel symbol '{0}' found: {1:#010x}".format(name, symbol_vaddr))
                return symbol_vaddr
        debug.debug("Requested kernel symbol '{0}' not found".format(name))
        return None

    def calculate(self):
        symbol_name = self._config.KSYMBOL
        if not symbol_name:
            debug.error("Please specify a kernel symbol name to extract (use option --ksymbol)")
        return (symbol_name, self.get_symbol(symbol_name))

    def render_text(self, outfd, data):
        symbol_name, symbol_vaddr = data
        if symbol_vaddr:
            outfd.write("Kernel symbol: {0} @ {1:#010x}\n".format(symbol_name, symbol_vaddr))
        else:
            outfd.write("Requested kernel symbol '{0}' not found\n".format(symbol_name))