from volatility.plugins.addrspaces import arm


class ArmAutoAddressSpace(arm.ArmAddressSpace):
    order = 850
    cache = False
    pae = False
    paging_address_space = True
    checkname = 'ArmAutoValidAS'