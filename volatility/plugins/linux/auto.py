from volatility.plugins.linux import common as linux_common


class AbstractLinuxAutoCommand(linux_common.AbstractLinuxCommand):
    """An abstract class that need to be inherited by all linux auto commands."""

    @staticmethod
    def is_valid_profile(profile):
        """Returns True if the plugin is valid for the current profile."""
        return (linux_common.AbstractLinuxCommand.is_valid_profile(profile) and
                profile.metadata.get('auto', False))