from volatility import obj
from volatility.plugins.linux import auto as linux_auto, common as linux_common
from volatility.plugins.linux.auto_ksymbol import linux_auto_ksymbol
from volatility.plugins.overlays.linux.linux_auto import task_struct


class linux_auto_pslist(linux_auto.AbstractLinuxAutoCommand):
    """Gather active tasks by walking the task_struct->tasks list"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        # Automatically initialize task_struct offsets
        task_struct.init_offsets(self.addr_space)

        ksymbol_command = linux_auto_ksymbol(self._config)
        init_task_addr = ksymbol_command.get_symbol('init_task')
        init_task = obj.Object('task_struct', offset=init_task_addr, vm=self.addr_space)
        yield init_task
        for task in init_task.tasks:
            yield task

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("DTB", "[addrpad]")])
        for task in data:
            self.table_row(outfd,
                           task.obj_offset,
                           task.comm,
                           0)