class BaseConnector:
    STATE={}; CONFIG={}; ACTION=None
    def __init__(self): self.results=[]; self.progress=[]
    def load_state(self): return BaseConnector.STATE
    def save_state(self,s): BaseConnector.STATE=s
    def get_config(self): return BaseConnector.CONFIG
    def add_action_result(self,r): self.results.append(r); return r
    def get_action_identifier(self): return BaseConnector.ACTION
    def save_progress(self,m): self.progress.append(m)
    def debug_print(self,*a): pass
    def get_container_id(self): return 42
