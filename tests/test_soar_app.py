"""Unit tests for the Kestrel Demo Containment SOAR app, run against a minimal stand-in
for the SOAR runtime (tests/phantom_stub) and a local mock HEC endpoint.
Run: python3 tests/test_soar_app.py"""
import sys, json, http.server, threading
import os
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,os.path.join(HERE,'phantom_stub')); sys.path.insert(0,os.path.join(HERE,'..','soar','kestreldemocontainment'))
import kestreldemocontainment_connector as k
from phantom.base_connector import BaseConnector as B
got=[]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        got.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"text":"Success","code":0}')
    def log_message(self,*a): pass
srv=http.server.HTTPServer(('127.0.0.1',18089),H); threading.Thread(target=srv.serve_forever,daemon=True).start()
def run(action, param, cfg=None):
    B.ACTION=action; B.CONFIG=cfg or {}
    c=k.KestrelDemoContainmentConnector(); c.initialize(); rv=c.handle_action(param); c.finalize()
    r=c.results[0]; return rv, r.message, r.data[:1]
fails=0
def check(name, cond, info=''):
    global fails
    print(('PASS ' if cond else 'FAIL ')+name, info if not cond else '')
    fails += (not cond)
hec={'hec_url':'http://127.0.0.1:18089','hec_token':'t','verify_ssl':False,'simulate_failure_for':'kes-dc01'}
rv,m,_=run('test_connectivity',{}); check('test connectivity (no HEC)', rv is True)
rv,m,_=run('test_connectivity',{},hec); check('test connectivity (HEC)', rv is True and got[-1]['sourcetype']=='esdemo:containment')
rv,m,d=run('disable_user',{'username':'KESTREL\\dchen','comment':'INV-1'},hec)
check('disable user normalizes domain user', rv and d[0]['target']=='dchen' and d[0]['state']=='disabled', m)
check('HEC event carries action+target', got[-1]['event']['action']=='disable_user' and got[-1]['event']['target']=='dchen' and got[-1]['index']=='esdemo')
rv,m,d=run('disable_user',{'username':'dchen@kestrel.example'},hec); check('disable twice says already', rv and 'already' in m, m)
rv,m,d=run('enable_user',{'username':'dchen'}); check('enable after disable', rv and d[0]['previous_state']=='disabled' and d[0]['state']=='enabled')
rv,m,d=run('block_ip',{'ip':'203.0.113.45'}); check('block ip', rv and d[0]['state']=='blocked')
rv,m,d=run('block_ip',{'ip':'999.1.1.1'}); check('invalid ip rejected', rv is False, m)
rv,m,d=run('unblock_ip',{'ip':'203.0.113.45'}); check('unblock ip', rv and d[0]['state']=='allowed')
rv,m,d=run('quarantine_device',{'hostname':'KES-WS-FIN-001'}); check('quarantine device lowercases', rv and d[0]['target']=='kes-ws-fin-001')
rv,m,d=run('quarantine_device',{'hostname':'kes-dc01'},hec); check('simulated failure', rv is False and 'simulated failure' in m, m)
rv,m,d=run('unquarantine_device',{'hostname':'kes-ws-fin-001'}); check('unquarantine', rv and d[0]['state']=='released')
rv,m,d=run('block_url',{'url':'https://kestrel-sso.example/login'}); check('block url', rv)
rv,m,d=run('delete_email',{'message_id':'<abc@x>'}); check('delete email', rv and d[0]['state']=='purged')
rv,m,d=run('reset_password',{'username':'slee'}); rv2,m2,_=run('reset_password',{'username':'slee'}); check('reset password repeatable', rv and rv2)
rv,m,d=run('block_ip',{'ip':''}); check('missing param', rv is False)
bad={'hec_url':'http://127.0.0.1:1','hec_token':'t'}
rv,m,d=run('block_ip',{'ip':'198.51.100.7'},bad); check('HEC down does not fail action', rv and 'HEC logging failed' in m, m)
rv,m,_=run('test_connectivity',{},bad); check('test connectivity reports HEC failure', rv is False, m)
# --- list handling (Guided Response) and reset
B.STATE={}
rv,m,d=run('disable_user',{'username':['slee']},hec); check('list param', rv and d[0]['target']=='slee' and got[-1]['event']['target']=='slee', m)
rv,m,d=run('reset_password',{'username':"['slee']"}); check('stringified list param', rv and d[0]['target']=='slee', m)
rv,m,d=run('block_ip',{'ip':'["203.0.113.45", "203.0.113.99"]'}); check('two IPs in one call', rv and 'Blocked IP 203.0.113.45' in m and '203.0.113.99' in m, m)
rv,m,d=run('block_ip',{'ip':'203.0.113.45, 203.0.113.99'}); check('comma list, already blocked', rv and m.count('already blocked')==2, m)
rv,m,d=run('quarantine_device',{'hostname':['kes-dc01','kes-ws-fin-001']},hec); check('partial simulated failure', rv and 'simulated failure' in m and 'Quarantined device kes-ws-fin-001' in m, m)
rv,m,d=run('delete_email',{'message_id':'<abc@x.example>'}); check('message id brackets stripped', rv and d[0]['target']=='abc@x.example', m)
B.ACTION='reset_demo_state'; B.CONFIG=hec
c=k.KestrelDemoContainmentConnector(); c.initialize(); rv=c.handle_action({}); c.finalize()
check('reset demo state', rv and all(v=={} for v in B.STATE.values()) and got[-1]['event']['action']=='reset_demo_state', c.results[0].message)
rv,m,d=run('disable_user',{'username':'slee'}); check('after reset, slee disabled fresh', rv and d[0]['previous_state']=='enabled', m)
print('FAILS',fails)
srv.shutdown()
sys.exit(1 if fails else 0)
