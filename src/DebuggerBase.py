
from .Interfaces import DebuggerInterface

class DebuggerBase( DebuggerInterface ):
    def __init__(self):
        """
        If used, defines the following shortcuts:
        bpc(self, index) = breakpointRemove(self, index)
        bpd(self, index) = breakpointDisable(self, index)
        bpe(self, index) = breakpointEnable(self, index)
        bpl = breakpointsList(self)
        bpx(self, address) = breakpointSet(self, address)
        g = run(self)
        r = contextShow(self)
        """
        self.bpc = self.breakpointRemove
        self.bpd = self.breakpointDisable
        self.bpe = self.breakpointEnable
        class BreakpointsListWrapper(object):
            def __init__(self, debugger):
                self._debugger = debugger
            def __repr__(self):
                return str(self._debugger.breakpointsList())
        self.bpl = BreakpointsListWrapper(self)
        self.bpx = self.breakpointSet
        class RunWrapper(object):
            def __init__(self, debugger):
                self._debugger = debugger
            def __repr__(self):
                self._debugger.run()
                return ""
        self.g = RunWrapper(self)
        class ShowContextWrapper(object):
            def __init__(self, debugger):
                self._debugger = debugger
            def __repr__(self):
                return str(self._debugger._contextShow())
        self.r = ShowContextWrapper(self)

