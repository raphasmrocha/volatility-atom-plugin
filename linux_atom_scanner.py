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
            if (task.comm == "atom") and (task.parent.comm == "upstart"):
                #print task.comm

                addr_space = task.get_process_address_space()
                print addr_space
                #matches = rules.match(data=data)
                #if matches:
                #    print matches[0].strings[0][0]




    def render_text(self, outfd, data):
        self.table_header(outfd, [("PID", "15"),
                                  ("Filename", "20"),
                                  ("Directory Path", "40")])
        for task, filepath in data:
            self.table_row(outfd,
                    task.pid,
                    filepath,
                    filename)

    def generator(self, data):
        for task, filepath in data:
            yield (0, [
                int(task.Pid),
                str(filename),
                str(filepath)
                ])

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Filename", str),
                         ("Directory Path", str)],
                         self.generator(data))
