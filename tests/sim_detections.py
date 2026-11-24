#!/usr/bin/env python3
"""Offline check: replay generator output through Python versions of each detection,
on the same schedule / window / suppression the Splunk detections use."""
import csv, ipaddress, json, os, random, re, sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "generator"))
import esdemo as g

random.seed(7)
HERE = os.path.dirname(os.path.abspath(__file__))
THREAT = {r["domain"] for r in csv.DictReader(open(os.path.join(HERE, "..", "content", "DA-ESS-esdemo", "lookups", "esdemo_threat_domains.csv")))}
ADMINS = {r["user"] for r in csv.DictReader(open(os.path.join(HERE, "..", "content", "DA-ESS-esdemo", "lookups", "esdemo_it_admins.csv")))}
ASSETS = {r["ip"]: r["nt_host"] for r in csv.DictReader(open(os.path.join(HERE, "..", "generator", "data", "esdemo_assets.csv")))}
TACTICS = {"T1566.002": ["initial-access"], "T1204.001": ["execution"], "T1078.004": ["initial-access", "persistence", "privilege-escalation", "stealth"],
           "T1059.001": ["execution"], "T1110.003": ["credential-access"], "T1569.002": ["execution"], "T1021.002": ["lateral-movement"],
           "T1136.002": ["persistence"], "T1048": ["exfiltration"], "T1046": ["discovery"], "T1560.001": ["collection"]}


def internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


# detection: name -> (finding?, mitre, fn(events)->list of result dicts, suppress fields, risk objects [(field,type)])
def d1(E):
    groups = defaultdict(list)
    for e in E:
        if e["sourcetype"] == "esdemo:email" and e["event"]["action"] == "delivered":
            groups[(e["event"]["message_id"], e["event"]["src_user"])].append(e["event"]["recipient"])
    out = []
    for (mid, su), rc in groups.items():
        if su.split("@")[1].lower() in THREAT:
            out.append({"message_id": mid, "src_user": su, "user": [r.split("@")[0] for r in set(rc)]})
    return out


def d2(E):
    s = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:proxy" and b["action"] == "allowed" and b["url_domain"] in THREAT:
            s.add((b["user"], b["src"], b["url_domain"]))
    return [{"user": u, "src": sr, "url_domain": d} for u, sr, d in s]


def d3(E):
    s = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:auth" and b["action"] == "success" and not internal(b["src"]):
            s.add((b["user"], b["src"]))
    return [{"user": u, "src": sr} for u, sr in s]


def d4(E):
    s = set()
    pat = re.compile(r"(\s-enc\s|\s-e\s|\s-ec\s|-EncodedCommand\s)", re.I)
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:endpoint:process" and b["process_name"].lower() in ("powershell.exe", "pwsh.exe") \
                and pat.search(b["process"] + " "):
            s.add((b["dest"], b["user"], b["parent_process_name"]))
    return [{"dest": d, "user": u, "parent": p} for d, u, p in s]


def d5(E):
    fails = defaultdict(set)
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:auth" and b["action"] == "failure":
            fails[b["src"]].add(b["user"])
    return [{"src": s} for s, u in fails.items() if len(u) >= 10]


def d6(E):
    fails = defaultdict(set); succ = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:auth":
            if b["action"] == "failure":
                fails[b["src"]].add(b["user"])
            else:
                succ.add((b["src"], b["user"]))
    return [{"user": u, "src": s} for s, u in succ if len(fails[s]) >= 10]


def d7(E):
    s = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:endpoint:process" and b["process_name"].lower() in ("psexec.exe", "psexec64.exe"):
            s.add((b["dest"], b["user"]))
    return [{"dest": d, "user": u} for d, u in s]


def d8(E):
    s = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:change" and b["action"] == "created" and b["src_user"] not in ADMINS:
            s.add((b["object"], b["src_user"]))
    return [{"object": o, "src_user": u} for o, u in s]


def d9(E):
    tot = defaultdict(int)
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:firewall" and b["action"] == "allowed":
            tot[(b["src"], b["dest"])] += b["bytes_out"]
    return [{"src": s, "dest": d, "src_host": ASSETS.get(s, s), "mb": v // 1048576}
            for (s, d), v in tot.items() if not internal(d) and v > 524288000]


def d10(E):
    dests = defaultdict(set); ports = defaultdict(set)
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:firewall":
            dests[b["src"]].add(b["dest"]); ports[b["src"]].add(b["dest_port"])
    return [{"src": s, "src_host": ASSETS.get(s, s)} for s in dests if len(dests[s]) >= 20 or len(ports[s]) >= 50]


def d12(E):
    s = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:endpoint:process" and b["process_name"].lower() in ("7z.exe", "7za.exe", "rar.exe", "winrar.exe") \
                and " -p" in b["process"]:
            s.add((b["dest"], b["user"]))
    return [{"dest": d, "user": u} for d, u in s]


def d11(E):
    s = set()
    for e in E:
        b = e["event"]
        if e["sourcetype"] == "esdemo:o365:audit" and b["Operation"] in ("New-InboxRule", "Set-InboxRule"):
            for p in b["Parameters"]:
                if p["Name"] in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo") and not p["Value"].lower().endswith("@kestrel.example"):
                    s.add(b["UserId"].split("@")[0])
    return [{"user": u} for u in s]


DETS = {
    "D1 Phishing email": (True, ["T1566.002"], d1, ["message_id"], [("user", "user")]),
    "D2 Browsed phishing domain": (False, ["T1204.001"], d2, ["user", "url_domain"], [("user", "user")]),
    "D3 External sign-in": (True, ["T1078.004"], d3, ["user", "src"], [("user", "user")]),
    "D4 Encoded PowerShell": (True, ["T1059.001"], d4, ["dest", "user"], [("user", "user"), ("dest", "system")]),
    "D5 Password spray": (True, ["T1110.003"], d5, ["src"], [("src", "system")]),
    "D6 Success after spray": (True, ["T1110.003", "T1078.004"], d6, ["user", "src"], [("user", "user")]),
    "D7 PsExec": (True, ["T1569.002", "T1021.002"], d7, ["user", "dest"], [("user", "user"), ("dest", "system")]),
    "D8 Account created by non-IT": (True, ["T1136.002"], d8, ["src_user", "object"], [("src_user", "user")]),
    "D9 Large outbound": (True, ["T1048"], d9, ["src", "dest"], [("src_host", "system")]),
    "D10 Network scan": (True, ["T1046"], d10, ["src"], [("src_host", "system")]),
    "D12 Protected archive": (False, ["T1560.001"], d12, ["user", "dest"], [("user", "user"), ("dest", "system")]),
}
GAP = {"D11 Mailbox forwarding (Detection Builder)": (True, ["T1114.003"], d11, ["user"], [("user", "user")])}
TACTICS["T1114.003"] = ["collection"]


def build_stream(minutes_before=10, minutes_after=30, with_demo=True, eps=2.0):
    world = g.World()
    T0 = 1_800_000_000.0
    E = []
    total = (minutes_before + minutes_after) * 60
    t = T0
    while t < T0 + total:
        E += g.baseline_batch(world, t, "sim", int(eps * 5))
        t += 5
    if with_demo:
        demo_start = T0 + minutes_before * 60
        for off, name in g.DEMO_TIMELINE:
            for so, evs in g.BUILDERS[name](world, demo_start + off, "sim", 1.0):
                E += evs
    E.sort(key=lambda e: e["time"])
    return T0, total, E


def simulate(include_gap=False, with_demo=True, label=""):
    T0, total, E = build_stream(with_demo=with_demo)
    dets = dict(DETS, **(GAP if include_gap else {}))
    findings = defaultdict(list)
    risk = []          # (time, entity, type, source, tactics)
    supp = {}
    fbd_supp = {}
    fbd = []
    t = T0 + 120
    while t <= T0 + total + 600:
        win = [e for e in E if t - 1200 <= e["time"] < t]
        for name, (is_f, mitre, fn, sfields, robj) in dets.items():
            for r in fn(win):
                key = (name,) + tuple(str(r.get(f)) for f in sfields)
                if key in supp and t - supp[key] < 1800:
                    continue
                supp[key] = t
                if is_f:
                    findings[name].append(r)
                for f, typ in robj:
                    vals = r[f] if isinstance(r[f], list) else [r[f]]
                    for v in vals:
                        risk.append((t, v, typ, name, sum((TACTICS[m] for m in mitre), [])))
        if (t - T0) % 180 < 120:   # FBD every 3 min
            ents = defaultdict(lambda: {"sources": set(), "tactics": set()})
            for rt, ent, typ, src, tac in risk:
                if t - 1800 <= rt <= t:
                    ents[(ent, typ)]["sources"].add(src); ents[(ent, typ)]["tactics"].update(tac)
            for ent, v in ents.items():
                if len(v["tactics"]) >= 3 and len(v["sources"]) >= 6:
                    if ent in fbd_supp and t - fbd_supp[ent] < 2400:
                        continue
                    fbd_supp[ent] = t
                    fbd.append((round((t - T0) / 60 - 10, 1), ent, sorted(v["sources"]), sorted(v["tactics"])))
        t += 120
    print(f"\n=== {label}")
    n = 0
    for name in dets:
        f = findings.get(name, [])
        is_f = dets[name][0]
        n += len(f) if is_f else 0
        ents = [", ".join(f"{k}={v}" for k, v in r.items() if k in ("user", "src", "dest", "src_user", "src_host", "parent", "object")) for r in f]
        print(f"  {name:44} {'findings' if is_f else 'risk-only'}: {len(f) if is_f else '-':>2}  {ents if is_f else ''}")
    for m, ent, s, tac in fbd:
        print(f"  FBD Multi-stage attack  at demo+{m}min  {ent}  sources={len(s)} tactics={tac}")
    n += len(fbd)
    print(f"  TOTAL findings: {n}")
    return n, findings, fbd


if __name__ == "__main__":
    nb, fb, fbdb = simulate(with_demo=False, label="40 minutes of baseline only (expect 0)")
    n1, f1, fbd1 = simulate(label="10 min baseline + full demo + 30 min baseline (Detection Builder not used)")
    n2, f2, fbd2 = simulate(include_gap=True, label="same, with the Detection Builder mailbox-forwarding detection enabled")
    ok = (nb == 0 and n1 == 12 and n2 == 13 and len(fbd1) == 1 and fbd1[0][1] == ("dchen", "user"))
    print("\nRESULT:", "PASS" if ok else "CHECK")
