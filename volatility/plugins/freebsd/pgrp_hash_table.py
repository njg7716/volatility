import volatility.plugins.freebsd.pslist as pslist
import volatility.obj as obj
import volatility.plugins.freebsd.common as common

class freebsd_pgrp_hash_table(pslist.freebsd_pslist):
    """ Walks the process group hash table """

    def calculate(self):
        common.set_plugin_members(self)
            
        pgrphash_addr = self.addr_space.profile.get_symbol("pgrphash") 
        pgrphash = obj.Object("unsigned long", offset = pgrphash_addr, vm = self.addr_space)

        pgrphashtbl_addr = self.addr_space.profile.get_symbol("pgrphashtbl")
        pgrphashtbl_ptr = obj.Object("Pointer", offset = pgrphashtbl_addr, vm = self.addr_space)
        pgrphash_array = obj.Object("Array", targetType = "pgrphashhead", count = pgrphash + 1, vm = self.addr_space, offset = pgrphashtbl_ptr)
    
        for plist in pgrphash_array:
            pgrp = plist.lh_first
    
            while pgrp:
                p = pgrp.pg_members.lh_first

                while p:
                    yield p
                    p = p.p_pglist.le_next 
    
                pgrp = pgrp.pg_hash.le_next