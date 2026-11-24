#!/usr/bin/env python3
"""
verify.py - send one test event per demo sourcetype to Splunk Cloud HEC.

Run it from your laptop after installing TA-esdemo and creating the HEC token.
No third-party packages needed (Python 3.8+ standard library only).

Usage
  export ESDEMO_HEC_TOKEN=<your esdemo_hec token>
  export ESDEMO_STACK=<your stack name>    # e.g. mycompany for mycompany.splunkcloud.com
  python3 verify.py
  python3 verify.py --stack mystack       # another Splunk Cloud stack
  python3 verify.py --url https://http-inputs-mystack.splunkcloud.com
  python3 verify.py --dry-run             # print the events, send nothing

The events carry esdemo_run=<run id> so they are easy to find and never trigger
detections (users and hosts are the benign baseline population).
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

DOMAIN = "kestrel.example"


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def build_events(run_id, now):
    common = {"esdemo_run": run_id, "esdemo_scenario": "verify"}
    events = [
        ("esdemo:auth", "kes-idp", {
            "action": "success", "app": "kestrel-sso", "user": "ytan",
            "src": "10.20.3.102", "dest": "kes-dc01", "authentication_method": "password+mfa",
            "signature": "User logged on", "signature_id": "4624", "reason": "",
        }),
        ("esdemo:endpoint:process", "kes-ws-eng-002", {
            "dest": "kes-ws-eng-002", "user": "ytan", "process_name": "code.exe",
            "process": "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\"",
            "process_path": "C:\\Program Files\\Microsoft VS Code\\Code.exe",
            "process_id": 4120, "process_guid": str(uuid.uuid4()),
            "parent_process_name": "explorer.exe", "parent_process": "C:\\Windows\\explorer.exe",
            "parent_process_id": 3008, "parent_process_path": "C:\\Windows\\explorer.exe",
            "original_file_name": "Code.exe", "process_hash": "SHA256=" + "a" * 64,
            "process_integrity_level": "medium",
        }),
        ("esdemo:email", "kes-mailgw", {
            "action": "delivered", "src_user": f"tnguyen@{DOMAIN}", "recipient": f"ytan@{DOMAIN}",
            "subject": "Team lunch on Friday", "message_id": f"<{uuid.uuid4()}@{DOMAIN}>",
            "src": "10.10.0.70", "file_name": "", "url": "", "signature": "clean",
            "direction": "internal",
        }),
        ("esdemo:proxy", "kes-proxy", {
            "action": "allowed", "src": "10.20.3.102", "user": "ytan",
            "url": "https://docs.python.org/3/library/json.html", "url_domain": "docs.python.org",
            "dest": "docs.python.org", "http_method": "GET", "status": 200,
            "bytes_in": 48211, "bytes_out": 812, "category": "Technology",
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "http_content_type": "text/html",
        }),
        ("esdemo:firewall", "kes-fw01", {
            "action": "allowed", "src": "10.20.3.102", "src_port": 51544,
            "dest": "10.10.0.20", "dest_port": 445, "transport": "tcp", "app": "smb",
            "bytes_in": 20400, "bytes_out": 3100, "direction": "internal", "rule": "allow-internal-smb",
        }),
        ("esdemo:change", "kes-dc01", {
            "action": "modified", "change_type": "AAA", "object_category": "user",
            "object": "ytan", "user": "ytan", "src_user": "jkim", "dest": "kes-dc01",
            "command": "Set-ADUser -Replace @{title='Software Engineer'}",
            "signature_id": "4738", "result": "success", "status": "success",
        }),
        ("esdemo:o365:audit", "office365", {
            "CreationTime": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "Workload": "Exchange", "RecordType": 1, "Operation": "Set-Mailbox",
            "UserId": f"ytan@{DOMAIN}", "ClientIP": "10.20.3.102", "ResultStatus": "Succeeded",
            "ObjectId": f"ytan@{DOMAIN}",
            "Parameters": [{"Name": "Identity", "Value": f"ytan@{DOMAIN}"},
                           {"Name": "AutoReplyState", "Value": "Disabled"}],
        }),
    ]
    out = []
    for i, (st, host, body) in enumerate(events):
        ts = now + i * 0.01
        body = dict(body, **common)
        if st != "esdemo:o365:audit":
            body = {"timestamp": iso(ts), **body}
        out.append({"time": round(ts, 3), "host": host, "source": "esdemo_verify",
                    "sourcetype": st, "event": body})
    return out


def send(url, token, events, context):
    data = "\n".join(json.dumps(e) for e in events).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Splunk {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20, context=context) as r:
        return r.status, r.read().decode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stack", default=os.environ.get("ESDEMO_STACK"))
    ap.add_argument("--url", default=os.environ.get("ESDEMO_HEC_URL"),
                    help="HEC base URL (default https://http-inputs-<stack>.splunkcloud.com)")
    ap.add_argument("--token", default=os.environ.get("ESDEMO_HEC_TOKEN"))
    ap.add_argument("--index", default=None, help="override the token's default index (normally esdemo)")
    ap.add_argument("--ca-bundle", default=os.environ.get("ESDEMO_CA_BUNDLE"),
                    help="custom CA bundle, e.g. if a corporate proxy re-signs TLS")
    ap.add_argument("--system-trust", action="store_true",
                    default=os.environ.get("ESDEMO_SYSTEM_TRUST") == "1",
                    help="trust the OS certificate store (macOS Keychain / Windows store); "
                         "fixes corporate TLS inspection. Needs: pip install truststore")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    run_id = "verify-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    events = build_events(run_id, time.time())
    if a.index:
        for e in events:
            e["index"] = a.index

    if a.dry_run:
        for e in events:
            print(json.dumps(e, indent=2))
        return 0

    if not a.token:
        print("ERROR: set ESDEMO_HEC_TOKEN or pass --token", file=sys.stderr)
        return 2
    if not (a.url or a.stack):
        print("ERROR: set ESDEMO_STACK (or --stack <stack> / --url <HEC base URL>)", file=sys.stderr)
        return 2
    base = (a.url or f"https://http-inputs-{a.stack}.splunkcloud.com").rstrip("/")
    url = base if base.endswith("/services/collector/event") else base + "/services/collector/event"
    if a.system_trust:
        try:
            import truststore
        except ImportError:
            print("ERROR: --system-trust needs the truststore package: python3 -m pip install truststore",
                  file=sys.stderr)
            return 2
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif a.ca_bundle:
        ctx = ssl.create_default_context(cafile=a.ca_bundle)
    else:
        ctx = ssl.create_default_context()

    print(f"Sending {len(events)} events to {url}")
    try:
        status, body = send(url, a.token, events, ctx)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        print(f"FAILED: HTTP {e.code} {detail}", file=sys.stderr)
        hints = {400: "malformed request or index not allowed for this token",
                 401: "token missing", 403: "token invalid or disabled",
                 404: "wrong URL - check the stack name"}
        if e.code in hints:
            print("Hint: " + hints[e.code], file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"FAILED: cannot reach {url}: {e.reason}", file=sys.stderr)
        if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            print("Hint: a security proxy is re-signing TLS. Run with --system-trust "
                  "(after: python3 -m pip install truststore), or --ca-bundle <corporate root CA .pem>.",
                  file=sys.stderr)
        else:
            print("Hint: check the stack name, VPN/proxy, the HEC IP allow list, or that HEC is enabled.",
                  file=sys.stderr)
        return 1
    except (OSError, ConnectionError) as e:  # includes RemoteDisconnected, ssl errors
        print(f"FAILED: connection to {url} broke: {e}", file=sys.stderr)
        print("Hint: TLS interception by a proxy? try --ca-bundle; otherwise retry.", file=sys.stderr)
        return 1

    print(f"HEC answered {status}: {body}")
    print(f"\nRun id: {run_id}")
    print("Check in Splunk (Search app, last 15 minutes):")
    print(f'  index=esdemo esdemo_run="{run_id}" | stats count by sourcetype, eventtype, tag')
    print("Or tell Claude the run id and it will check every data model for you.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
