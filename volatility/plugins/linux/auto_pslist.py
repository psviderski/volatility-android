from volatility import debug, obj
from volatility.plugins.linux import auto as linux_auto, common as linux_common
from volatility.plugins.linux.auto_ksymbol import linux_auto_ksymbol
from volatility.plugins.linux.auto_dtblist import linux_auto_dtblist
from volatility.plugins.overlays.linux.linux_auto import task_struct, mm_struct


class linux_auto_pslist(linux_auto.AbstractLinuxAutoCommand):
    """Gather active tasks by walking the task_struct->tasks list"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        # Automatically initialize task_struct offsets
        task_struct.init_offsets(self.addr_space)
        if not all([task_struct.is_offset_defined(memname) for memname in ['comm', 'tasks', 'mm']]):
            debug.warning("Some of required members of 'task_struct' structure were not found.")
            return

        ksymbol_command = linux_auto_ksymbol(self._config)
        init_task_addr = ksymbol_command.get_symbol('init_task')
        if init_task_addr is None:
            debug.warning("Can't locate the first process (swapper).")
            return
        init_task = obj.Object('task_struct', offset=init_task_addr, vm=self.addr_space)
        tasks_dtb_list = []
        for task in init_task.tasks:
            if mm_struct.is_offset_defined('pgd'):
                pgd = task.mm.pgd
                if pgd:
                    tasks_dtb_list.append(self.addr_space.vtop(pgd))
            yield task
        # List unnamed potentially hidden or terminated processes
        # auto-discovered by dtblist command.
        dtblist_command = linux_auto_dtblist(self._config)
        for dtb in dtblist_command.calculate():
            if dtb not in tasks_dtb_list:
                yield dtb

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("DTB", "[addrpad]")])
        for task in data:
            if isinstance(task, task_struct):
                dtb = obj.NoneObject()
                if mm_struct.is_offset_defined('pgd'):
                    pgd = task.mm.pgd
                    dtb = self.addr_space.vtop(pgd) if pgd else pgd
                self.table_row(outfd,
                               task.obj_offset,
                               task.comm,
                               dtb)
            else:  # dtblist
                self.table_row(outfd,
                               obj.NoneObject(),
                               obj.NoneObject(),
                               task)
