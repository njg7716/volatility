import volatility.plugins.freebsd.pstasks as pstasks

class freebsd_pstree(pstasks.freebsd_pstasks):
    """ Show parent/child relationship of processes """

    def render_text(self, outfd, data):
        self.procs_hash = {}
        self.procs_seen = {}

        outfd.write("{0:20s} {1:15s} {2:15s}\n".format("Name", "Pid", "Uid"))

        for proc in data:
            self.procs_hash[proc.p_pid] = proc

        for pid in sorted(self.procs_hash.keys()):
            proc = self.procs_hash[pid]
            self._recurse_task(outfd, proc, 0)

    def _recurse_task(self, outfd, proc, level):
        if proc.p_pid in self.procs_seen:
            return

        proc_name = "." * level + proc.p_comm

        outfd.write("{0:20s} {1:15s} {2:15s}\n".format(proc_name, str(proc.p_pid), str(proc.p_ucred)))
  
        self.procs_seen[proc.p_pid] = 1
        
        proc = proc.p_children.lh_first

        while proc.is_valid():
            self._recurse_task(outfd, proc, level + 1)
            proc = proc.p_sibling.le_next