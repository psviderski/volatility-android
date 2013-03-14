import volatility.plugins.addrspaces.intel as intel


class ArmAutoAddressSpace(intel.JKIA32PagedMemory):
    order = 850
    cache = False
    pae = False
    paging_address_space = True
    checkname = 'ArmAutoValidAS'

