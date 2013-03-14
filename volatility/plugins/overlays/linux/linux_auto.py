import volatility.obj as obj


linux_auto_overlay = {
    'VOLATILITY_MAGIC': [None, {
        'ArmAutoValidAS': [0x0, ['VolatilityLinuxAutoARMValidAS']],
    }],
}


class LinuxAuto(obj.Profile):
    """An auto-discovery Profile for Linux ARM"""
    _md_os = 'linux'
    _md_memory_model = '32bit'
    _md_auto = True

    def __init__(self, *args, **kwargs):
        obj.Profile.__init__(self, *args, **kwargs)

    def get_symbol(self, sym_name):
        return None


class VolatilityLinuxAutoARMValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space.

    Used with the ARM auto-detect profile.

    """
    def generate_suggestions(self):
        # TODO: write some heuristics
        yield True


class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        yield 0x4000  # TODO: auto-discover this value


class LinuxAutoOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(linux_auto_overlay)


class LinuxAutoObjectClasses(obj.ProfileModification):
    """ Makes slight changes to the DTB checker """
    conditions = {'os': lambda x: x == 'linux',
                  'auto': lambda x: x}
    before = ['LinuxObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'VolatilityDTB': VolatilityDTB,
            'VolatilityLinuxAutoARMValidAS': VolatilityLinuxAutoARMValidAS,
        })