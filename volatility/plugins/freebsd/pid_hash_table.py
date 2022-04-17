import volatility.plugins.freebsd.pslist as pslist
import volatility.obj as obj
import volatility.plugins.freebsd.common as common

class freebsd_pid_hash_table(pslist.freebsd_pslist):
    """ Walks the pid hash table """

    def calculate(self):
        common.set_plugin_members(self)
            
        pidhash_addr = self.addr_space.profile.get_symbol("pidhash") 
        pidhash = obj.Object("unsigned long", offset = pidhash_addr, vm = self.addr_space)

        pidhashtbl_addr = self.addr_space.profile.get_symbol("pidhashtbl")
        pidhashtbl_ptr = obj.Object("Pointer", offset = pidhashtbl_addr, vm = self.addr_space)
        pidhash_array = obj.Object("Array", targetType = "next", count = pidhash + 1, vm = self.addr_space, offset = pidhashtbl_ptr)
    
        for plist in pidhash_array:
            p = plist.lh_first.dereference()
    
            while p:
                yield p                
                p = p.p_hash.le_next.dereference()