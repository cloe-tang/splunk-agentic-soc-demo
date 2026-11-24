class ActionResult:
    def __init__(self, param=None):
        self.param=param or {}; self.data=[]; self.summary={}; self.status=None; self.message=None
    def set_status(self, status, message=None):
        self.status=status; self.message=message; return status
    def add_data(self,d): self.data.append(d)
    def update_summary(self,s): self.summary.update(s)
    def get_data(self): return self.data
