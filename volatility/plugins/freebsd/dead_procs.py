import volatility.obj as obj
import volatility.plugins.freebsd.common as common
import volatility.plugins.freebsd.list_zones as list_zones
import volatility.plugins.freebsd.pslist as pslist

class freebsd_dead_procs(pslist.freebsd_pslist):
    """ Prints terminated/de-allocated processes """

    def calculate(self):
        common.set_plugin_members(self)
    
        zones = list_zones.freebsd_list_zones(self._config).calculate()

        for zone in zones:
            name = str(zone.zone_name.dereference())
            if name == "proc":
                procs = zone.get_free_elements("proc")        
                for proc in procs:
                    yield proc