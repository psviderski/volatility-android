import volatility.debug as debug
import volatility.obj as obj
from struct import unpack


ARM_PGD_SIZE = 0x4000  # 16 KB
ARM_PGD_ENTRIES = 4096
ARM_PGD_ENTRY_SIZE = 4

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

    def _is_valid_pgd(self, pgd_addr):
        """Checks if PGD table starting at pgd_addr is valid.

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
        first_kernel_entry = ARM_PGD_ENTRIES / 4 * 3
        first_kernel_entry_offset = pgd_addr + first_kernel_entry * ARM_PGD_ENTRY_SIZE
        valid_kernel_entries = 0
        for addr in xrange(first_kernel_entry_offset, pgd_addr + ARM_PGD_SIZE, ARM_PGD_ENTRY_SIZE):
            (pgd_entry, ) = unpack('<I', self.obj_vm.read(addr, ARM_PGD_ENTRY_SIZE))
            if (pgd_entry & 0x7ff) == 0x40e:
                valid_kernel_entries += 1
        valid_kernel_entries_ratio = 1.0 * valid_kernel_entries / min(as_size, 896)  # FIXME 896?
        if valid_kernel_entries_ratio > VALID_KERNEL_ENTRIES_THRESHOLD:
            debug.debug("Found {0} valid kernel entries in a PGD table at physical address {1:#x}. "
                        "Address space size: {2} MB.".format(valid_kernel_entries,
                                                             pgd_addr,
                                                             as_size))
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
        else:
            yield None


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