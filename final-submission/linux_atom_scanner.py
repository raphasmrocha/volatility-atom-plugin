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

    #def build_conf(self):
    #    yara_conf = conf.ConfObject()

    #    yara_conf.readonly = {}
    #    yara_conf.PROFILE = self._config.PROFILE
    #    yara_conf.LOCATION = self._config.LOCATION

    #    return yara_conf

    def convert_byte_to_string(char_array):
        return "".join(map(chr,bytes))
    
    def get_file_path(match):
        return match.split("/",1)[1]

    def get_file_name(filepath):
        fn = filepath.split("/")
        return fn[len(fn)-1]

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
        tasks = linux_pslist.linux_pslist(self._config).calculate()
        
        #yara_conf = self.build_conf()
        #y = linux_yarascan.

        # matches "file://
        signatures = {
                'filepath':'rule fp {strings: $a = {22 66 69 6c 65 3a 2f 2f} condition: $a}'
        }
        rules = yara.compile(sources=signatures)    

        #data = "\"file://kjkdf/skdjf/sdkjf"
        #
        #matches = rules.match(data=data)
        #if matches:
        #    print "match found"


        for task in tasks:
            # parent of all atom processes
            if (task.comm == "atom"):

                yield task
                #print task.comm
                #addr_space = task.get_process_address_space()
                #print addr_space
                #matches = rules.match(data=data)
                #if matches:
                #    print matches[0].strings[0][0]




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
