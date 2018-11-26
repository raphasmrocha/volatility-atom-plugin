import volatility.obj as obj
import volatility.utils as utils

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.linux_yarascan as linux_yarascan

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class linux_atom_scanner(linux_pslist.linux_pslist):
    """Gets filepaths of files open in Atom """

    # returns true if a relevant file opened in atom was found
    def filter_path(self, filepath):
        filter_list = ["dev", "sys", "opt", "usr", "var"]
        path = filepath.split("/")
        if len(path) == 1:
            return False
        if path[1] in filter_list:
            return False
        for index in path:
            if len(index) > 0  and index[0] == '.':
                return False
        return True

    def calculate(self):
        linux_common.set_plugin_members(self)

        # runs pslist plugin
        tasks = linux_pslist.linux_pslist(self._config).calculate()
        
        for task in tasks:
            # gets all process with name "atom"
            if (task.comm == "atom"):
                yield task

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "[addrpad]"),
                                  ("PID", "6"),
                                  ("PPID", "6"),
                                  ("Name", "10"),
                                  ("Path", "50")])
        for task in data:
            for filp, fd in task.lsof():
                if self.filter_path(linux_common.get_path(task,filp)):
                    self.table_row(outfd,
                                   task.obj_offset,
                                   task.pid,
                                   task.parent.pid,
                                   task.comm,
                                   linux_common.get_path(task,filp))

    def generator(self, data):
        for task in data:
            for filp, fd in task.lsof():
                if self.filter_path(linux_common.get_path(task,filp)):
                    yield (0, [
                        Address(task.obj_offset),
                        int(task.pid),
                        int(task.parent.pid),
                        str(task.comm),
                        str(linux_common.get_path(task, filp))
                        ])

    def unified_output(self, data):
        return TreeGrid([("address", str),
                         ("Pid", int),
                         ("PPid", int),
                         ("name", str),
                         ("path", str)],
                         self.generator(data))
