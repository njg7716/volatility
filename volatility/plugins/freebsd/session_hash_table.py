import volatility.plugins.freebsd.pslist as pslist
import volatility.obj as obj
import volatility.plugins.freebsd.common as common
from volatility.renderers import TreeGrid

class freebsd_list_sessions(pslist.freebsd_pslist):
    """ Enumerates sessions """

    def calculate(self):
        common.set_plugin_members(self)
            
        shash_addr = self.addr_space.profile.get_symbol("_sesshash") 
        shash = obj.Object("unsigned long", offset = shash_addr, vm = self.addr_space)

        shashtbl_addr = self.addr_space.profile.get_symbol("_sesshashtbl")
        shashtbl_ptr = obj.Object("Pointer", offset = shashtbl_addr, vm = self.addr_space)
        shash_array = obj.Object(theType = "Array", targetType = "sesshashhead", count = shash + 1, vm = self.addr_space, offset = shashtbl_ptr)
    
        for sess in shash_array:
            s = sess.lh_first
    
            while s:
                yield s                
                s = s.s_hash.le_next

    def unified_output(self, data):
        return TreeGrid([("Leader (Pid)", int),
                        ("Leader (Name)", str),
                        ("Login Name", str),
                        ], self.generator(data))

    def generator(self, data):
        for sess in data:
            pid = -1
            pname = "<INVALID LEADER>"
            if sess.s_leader:
                pid  = sess.s_leader.p_pid
                pname = sess.s_leader.p_comm
                    
            yield(0, [
                int(pid),
                str(pname),
                str(sess.s_login),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Leader (Pid)",  "8"),
                                  ("Leader (Name)", "20"),
                                  ("Login Name", "25")])

        for sess in data:
            pid = -1
            pname = "<INVALID LEADER>"
            if sess.s_leader:
                pid  = sess.s_leader.p_pid
                pname = sess.s_leader.p_comm
                    
            self.table_row(outfd, pid, pname, sess.s_login)