import volatility.obj as obj
import volatility.plugins.freebsd.common as common
from volatility.renderers import TreeGrid

class freebsd_list_zones(common.AbstractFreebsdCommand):
    """ Prints active zones """

    def calculate(self):
        common.set_plugin_members(self)

        first_zone_addr = self.addr_space.profile.get_symbol("proc_zone")
        if first_zone_addr:
            zone_ptr = obj.Object("Pointer", offset = first_zone_addr, vm = self.addr_space)
            zone = zone_ptr.dereference_as("zone")

            while zone:
                yield zone
                zone = zone.next_zone       
        else:
            zone_ptr = self.addr_space.profile.get_symbol("vm_object_zinit")
            zone_arr = obj.Object(theType="Array", targetType="zones", vm = self.addr_space, count = 256, offset = zone_ptr)

            for zone in zone_arr:
                if zone.is_valid():
                    yield zone
    
    def unified_output(self, data):
        return TreeGrid([("Name", str),
                         ("Active Count", int),
                         ("Free Count", int),
                         ("Element Size", int)
                        ], self.generator(data))

    def generator(self, data):
        for zone in data:
            name = zone.zone_name.dereference().replace(" ", ".")
    
            # sum_count was introduced in 10.8.x
            # do not want to overlay as 0 b/c we mess up subtraction
            sum_count = "N/A"
            if hasattr(zone, "sum_count"):
                sum_count = zone.sum_count - zone.count
            yield(0, [
                str(name),
                int(zone.count),
                int(sum_count),
                int(zone.elem_size),
            ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "30"), ("Active Count", ">10"), ("Free Count", ">10"), ("Element Size", ">10")])
        for zone in data:
            name = zone.zone_name.dereference().replace(" ", ".")
    
            # sum_count was introduced in 10.8.x
            # do not want to overlay as 0 b/c we mess up subtraction
            sum_count = "N/A"
            if hasattr(zone, "sum_count"):
                sum_count = zone.sum_count - zone.count

            self.table_row(outfd, name, zone.count, sum_count, zone.elem_size)