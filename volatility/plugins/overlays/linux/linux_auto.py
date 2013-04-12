import volatility.debug as debug
import volatility.obj as obj
from struct import unpack


ARM_PGD_SIZE = 0x4000  # 16 KB
ARM_PGD_ENTRIES = 4096
ARM_PGD_ENTRY_SIZE = 4
# Entry offsets
ARM_PGD_DOMAIN_OFFSET = 5

linux_auto_overlay = {
    'VOLATILITY_MAGIC': [None, {
        'ArmAutoValidAS': [0x0, ['VolatilityLinuxAutoARMValidAS']],
    }],
}


class AbstractLinuxAutoProfile(obj.Profile):
    """An abstract auto-discovery profile for Linux."""
    _md_os = 'linux'
    _md_memory_model = '32bit'
    _md_auto = True

    def __init__(self, *args, **kwargs):
        obj.Profile.__init__(self, *args, **kwargs)

    def get_symbol(self, sym_name):
        return None


class LinuxAutoARM(AbstractLinuxAutoProfile):
    """An auto-discovery profile for Linux ARM."""
    _md_arch = 'ARM'


class VolatilityLinuxAutoARMValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space.

    Used with the ARM auto-detect profile.

    """

    def generate_suggestions(self):
        # TODO: write some heuristics
        yield True


class VolatilityDTBARM(obj.VolatilityMagic):
    """A scanner for DTB values in an ARM image."""

    def _is_valid_pgd_kernel_space(self, pgd_addr):
        """Checks if kernel space entries in PGD table are valid.

        In case of 3G/1G User Space/Kernel Space mapping of virtual memory,
        the last quarter (entries 3072-4095) of a PGD table maintains Kernel's
        virtual address space mapping. Each of these entries maps 1 MB of physical
        memory. So their number should be approximately equal to the amount of
        physical memory in megabytes.

        """
        VALID_KERNEL_ENTRIES_THRESHOLD = 0.8  # 80%
        # Address space size in bytes
        as_size = sum(map(lambda addr_size: addr_size[1],
                          self.obj_vm.get_available_addresses()))
        # Address space size in megabytes
        as_size >>= 20
        pgd_page = self.obj_vm.read(pgd_addr, ARM_PGD_SIZE)
        first_kernel_entry = ARM_PGD_ENTRIES / 4 * 3
        valid_kernel_entries = 0
        for entry_num in xrange(first_kernel_entry, ARM_PGD_ENTRIES):
            entry_offset = entry_num * ARM_PGD_ENTRY_SIZE
            (pgd_entry, ) = unpack('<I', pgd_page[entry_offset:entry_offset + ARM_PGD_ENTRY_SIZE])
            #if (pgd_entry & 0xfff) == 0b010001001110:  # TODO domain 0
            if (pgd_entry & 0b110000001111) == 0b010000001110:
                # bits[1:0] == 0b10: 'pgd_entry' is a section or a supersection descriptor
                # AP == b01, C == 1, B == 1
                valid_kernel_entries += 1
        #debug.debug("Valid kernel entrie: {0}".format(valid_kernel_entries))
        valid_kernel_entries_ratio = 1.0 * valid_kernel_entries / min(as_size, 896)  # FIXME 896?
        if valid_kernel_entries_ratio > VALID_KERNEL_ENTRIES_THRESHOLD:
            debug.debug("Found {0} valid kernel entries in a PGD table at physical address {1:#x}. "
                        "Address space size: {2} MB.".format(valid_kernel_entries,
                                                             pgd_addr,
                                                             as_size))
            return True
        return False

    def _is_valid_pgd_user_space(self, pgd_addr):
        """Checks if user space entries in PGD table are valid.

        Linux kernel doesn't use fine page tables to map memory, so there
        shouldn't be any fine page table descriptor in a PGD table.

        """
        pgd_page = self.obj_vm.read(pgd_addr, ARM_PGD_SIZE)
        #define TASK_SIZE  (UL(CONFIG_PAGE_OFFSET) - UL(0x01000000))
        user_entries = ARM_PGD_ENTRIES / 4 * 3 - 16  # the last 16M is kernel module space
        for entry_num in xrange(user_entries):
            entry_offset = entry_num * ARM_PGD_ENTRY_SIZE
            (pgd_entry, ) = unpack('<I', pgd_page[entry_offset:entry_offset + ARM_PGD_ENTRY_SIZE])
            # TODO: domain user (1)
            if (pgd_entry & 0b11) == 0b11:  # reserved
                debug.debug("Found incorrect page table descriptor (entry #{0}) in a PGD table "
                            "at physical address {1:#x}.".format(entry_num, pgd_addr))
                return False
        return True

    def _is_valid_pgd(self, pgd_addr):
        """Checks if PGD table starting at pgd_addr is valid."""
        if self._is_valid_pgd_kernel_space(pgd_addr) and self._is_valid_pgd_user_space(pgd_addr):
            debug.debug("Found a valid PGD table at physical address {0:#x}.".format(pgd_addr))
            return True
        return False

    def generate_suggestions(self):
        """Tries to locate DTBs.

        Uses signature method based on hardware structures.

        """
        for phys_addr, size in self.obj_vm.get_available_addresses():
            # PGD table is 16 KB aligned
            for addr in xrange(phys_addr, phys_addr + size, ARM_PGD_SIZE):
                if self._is_valid_pgd(addr):
                    debug.debug("Located a DTB at physical address {0:#x}".format(addr))
                    yield addr


class LinuxAutoOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(linux_auto_overlay)


class LinuxAutoObjectClasses(obj.ProfileModification):
    """Makes slight changes to the DTB checker."""
    conditions = {'os': lambda x: x == 'linux',
                  'auto': lambda x: x}
    before = ['LinuxObjectClasses']

    def modification(self, profile):
        if profile.metadata.get('arch', 'unknown') == 'ARM':
            VolatilityDTB = VolatilityDTBARM
        else:  # TODO: implement other architectures (x86, x86_64)
            return
        profile.object_classes.update({
            'VolatilityDTB': VolatilityDTB,
            'VolatilityLinuxAutoARMValidAS': VolatilityLinuxAutoARMValidAS,
        })
