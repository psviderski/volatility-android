from struct import unpack
from copy import deepcopy
import volatility.debug as debug
import volatility.obj as obj
from volatility.plugins.linux.auto_ksymbol import linux_auto_ksymbol


ARM_PGD_SIZE = 0x4000  # 16 KB
ARM_PGD_ENTRIES = 4096
ARM_PGD_ENTRY_SIZE = 4
# Entry offsets
ARM_PGD_DOMAIN_OFFSET = 5

linux_auto_vtypes = {
    'list_head': [8, {
        'next': [0, ['pointer', ['list_head']]],
        'prev': [4, ['pointer', ['list_head']]]
    }],
}
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
            if (pgd_entry & 0b1001000110000001111) == 0b0000000010000001110:
                # bits[1:0] == 0b10: 'pgd_entry' is a section or a supersection descriptor
                # AP == b01, C == 1, B == 1
                valid_kernel_entries += 1
            elif (pgd_entry & 0b11) == 0b11:  # reserved
                #debug.debug("Found incorrect (reserved) page table descriptor (entry #{0}) in a PGD table "
                #            "at physical address {1:#x}.".format(entry_num, pgd_addr))
                return False
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
            #if (pgd_entry & 0b10) == 0b10:  # reserved or section Warning: 1 miss on HTC and rPi
                debug.debug("Found incorrect (reserved) page table descriptor (entry #{0}) in a PGD table "
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
        debug.debug("Available physical memory chunks")
        for phys_addr, size in self.obj_vm.get_available_addresses():
            debug.debug("{0:#x}-{1:#x} : {2} bytes".format(phys_addr, phys_addr + size - 1, size))
        for phys_addr, size in self.obj_vm.get_available_addresses():
            # PGD table is 16 KB aligned
            for addr in xrange(phys_addr, phys_addr + size, ARM_PGD_SIZE):
                if self._is_valid_pgd(addr):
                    debug.debug("Located a DTB at physical address {0:#x}".format(addr))
                    yield addr


class LinuxAutoVTypes(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.vtypes.update(linux_auto_vtypes)


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
            'task_struct': task_struct,
            'mm_struct': mm_struct,
            'VolatilityDTB': VolatilityDTB,
            'VolatilityLinuxAutoARMValidAS': VolatilityLinuxAutoARMValidAS,
        })


class AutoCType(obj.CType):
    vtypes = {}
    vm = None

    @classmethod
    def _update_profile(cls):
        """Add defined vtypes to the profile"""
        vtypes = deepcopy(cls.vtypes)
        struct_name = vtypes.iterkeys().next()
        for member_name, member_vtype in vtypes[struct_name][1].items():
            if member_vtype[0] is None:
                del vtypes[struct_name][1][member_name]
        cls.vm.profile.add_types(vtypes)

    @classmethod
    def is_offset_defined(cls, memname):
        members = cls.vtypes[cls.__name__][1]
        return memname in members and members[memname][0] is not None


class task_struct(AutoCType):
    MAX_SIZE = 0x600

    initialized = False
    vtypes = {
        'task_struct': [None, {
            'tasks': [None, ['list_head']],
            'mm': [None, ['pointer', ['mm_struct']]],
            'comm': [None, ['String', dict(length=16)]],
        }],
    }
    vm = None

    @classmethod
    def _init_offset_comm(cls):
        ksymbol_command = linux_auto_ksymbol(cls.vm.get_config())
        swapper_task_addr = ksymbol_command.get_symbol('init_task')
        if swapper_task_addr is None:
            return
        swapper_task_data = cls.vm.read(swapper_task_addr, cls.MAX_SIZE)
        comm_offset = swapper_task_data.find('swapper')
        if comm_offset != -1:
            debug.debug("Found 'task_struct->comm' offset: {0}".format(comm_offset))
            cls.vtypes['task_struct'][1]['comm'][0] = comm_offset
            cls._update_profile()
        else:
            debug.debug("Can't find 'task_struct->comm' offset")

    @classmethod
    def _init_offset_tasks(cls):
        if not cls.is_offset_defined('comm'):
            return
        ksymbol_command = linux_auto_ksymbol(cls.vm.get_config())
        swapper_task_addr = ksymbol_command.get_symbol('init_task')
        for tasks_offset in xrange(0, cls.MAX_SIZE, 4):
            cls.vtypes['task_struct'][1]['tasks'][0] = tasks_offset
            cls._update_profile()
            swapper_task = obj.Object('task_struct', offset=swapper_task_addr, vm=cls.vm)
            # Check first two tasks, they should be called 'init' and 'kthreadd'
            tasks_iterator = iter(swapper_task.tasks)
            try:
                init_task = tasks_iterator.next()
                if str(init_task.comm) == 'init':
                    kthreadd_task = tasks_iterator.next()
                    if str(kthreadd_task.comm) == 'kthreadd':
                        debug.debug("Found 'task_struct->tasks' offset: {0}".format(tasks_offset))
                        return
            except StopIteration:
                pass
        debug.debug("Can't find 'task_struct->tasks' offset")
        # Reset not found 'tasks' offset
        cls.vtypes['task_struct'][1]['tasks'][0] = None
        cls._update_profile()

    @classmethod
    def _init_offset_mm(cls):
        """Brute-forces the offset of 'mm_struct *mm' below the found 'list_head tasks' structure."""
        if not cls.is_offset_defined('tasks'):
            return
        ksymbol_command = linux_auto_ksymbol(cls.vm.get_config())
        swapper_task_addr = ksymbol_command.get_symbol('init_task')
        swapper_task = obj.Object('task_struct', offset=swapper_task_addr, vm=cls.vm)
        tasks_iterator = iter(swapper_task.tasks)
        try:
            init_task = tasks_iterator.next()
        except StopIteration:
            debug.debug("Can't get the next task after 'swapper' in tasks list")
            return
        # Start brute-force from the bottom of 'list_head tasks' structure
        mm_offset_start = cls.vtypes['task_struct'][1]['tasks'][0] + swapper_task.tasks.size()
        for mm_offset in xrange(mm_offset_start, mm_offset_start + 0x40, 4):
            mm_ptr = obj.Object('Pointer', offset=swapper_task.obj_offset + mm_offset, vm=cls.vm)
            if mm_ptr.v() != 0:  # 'mm' field for kernel threads is always NULL
                continue
            # Check 'mm' and 'active_mm' pointers in the 'task_struct' structure of 'init' process
            mm_ptr = obj.Object('Pointer', offset=init_task.obj_offset + mm_offset, vm=cls.vm)
            active_mm_ptr = obj.Object('Pointer', offset=init_task.obj_offset + mm_offset + 4, vm=cls.vm)
            if mm_ptr.v() != active_mm_ptr.v() or mm_ptr.v() < 0xc0000000 or not mm_ptr:
                continue
            # Check if the first member of 'mm_struct' points to 'vm_area_struct'
            mmap_ptr = obj.Object('Pointer', offset=mm_ptr.dereference().obj_offset, vm=cls.vm)
            mmap_struct = mmap_ptr.dereference()
            if not mmap_struct:
                continue
            # Check if there is a member of 'vm_area_struct' structure that points back to 'mm_struct'
            #
            # Before kernel versions 3.8:
            #     struct vm_area_struct {
            #         struct mm_struct * vm_mm;  <---
            #         unsigned long vm_start;
            #         unsigned long vm_end;
            #         ...
            #     }
            # Since kernel versions 3.8:
            #     struct vm_area_struct {
            #         unsigned long vm_start;
            #         unsigned long vm_end;
            #         ...
            #         struct mm_struct * vm_mm;  <---
            #     }
            is_vm_mm_found = False
            for vm_mm_offset in xrange(0, 0x64, 4):
                vm_mm = obj.Object('Pointer', offset=mmap_struct.obj_offset + vm_mm_offset, vm=cls.vm)
                if vm_mm.v() == mm_ptr.v():
                    is_vm_mm_found = True
                    break
            if not is_vm_mm_found:
                continue
            cls.vtypes['task_struct'][1]['mm'][0] = mm_offset
            cls._update_profile()
            debug.debug("Found 'task_struct->mm' offset: {0}".format(mm_offset))
            # Init offsets of 'mm_struct' structure
            mm_struct.init_offsets(cls.vm)
            return
        debug.debug("Can't find 'task_struct->mm' offset")

    # TODO: Think about a better way to lazy initialize offsets.
    @classmethod
    def init_offsets(cls, vm):
        if not cls.initialized:
            cls.vm = vm
            cls._init_offset_comm()
            cls._init_offset_tasks()
            cls._init_offset_mm()
            cls.initialized = True


class mm_struct(AutoCType):
    initialized = False
    vtypes = {
        'mm_struct': [None, {
            'pgd': [None, ['unsigned int']],
        }],
    }
    vm = None

    @classmethod
    def _init_offset_pgd(cls):
        if not task_struct.is_offset_defined('mm'):
            return
        ksymbol_command = linux_auto_ksymbol(cls.vm.get_config())
        swapper_task_addr = ksymbol_command.get_symbol('init_task')
        swapper_task = obj.Object('task_struct', offset=swapper_task_addr, vm=cls.vm)
        init_task = iter(swapper_task.tasks).next()
        init_task_mm = init_task.mm.dereference()
        for pgd_offset in xrange(0, 0x100, 4):
            pgd = obj.Object('Pointer', offset=init_task_mm.obj_offset + pgd_offset, vm=cls.vm)
            if not pgd:
                continue
            dtb = cls.vm.vtop(pgd.v())
            init_task_as = cls.vm.__class__(cls.vm.base, cls.vm.get_config(), dtb=dtb)
            if init_task_as.vtop(pgd.v()) == dtb:
                cls.vtypes['mm_struct'][1]['pgd'][0] = pgd_offset
                cls._update_profile()
                debug.debug("Found 'mm_struct->pgd' offset: {0}".format(pgd_offset))
                return
        debug.debug("Can't find 'mm_struct->pgd' offset")

    @classmethod
    def init_offsets(cls, vm):
        if not cls.initialized:
            cls.vm = vm
            cls._init_offset_pgd()
            cls.initialized = True
