#!/usr/bin/env python3
"""
Build DA-ESS-esdemo: the ES 8 detection content for the Kestrel Systems demo.

Detections are defined once here as Python data and rendered into
savedsearches.conf, so escaping, risk JSON and annotations stay consistent.

Timing model (tuned for a 30-minute live demo):
  event-based detections   cron */2, look back 20 minutes, suppressed 30 minutes per entity
  finding-based detection  cron */3, rolling 30-minute window, suppressed 40 minutes per entity
Detections search the CIM data models with summariesonly=false, so they see new
events within one schedule (no wait for data model acceleration).
"""
import json
import os
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "DA-ESS-esdemo")
STORY = "Kestrel Demo - Finance Account Takeover"

INTERNAL = ('(cidrmatch("10.0.0.0/8", {f}) OR cidrmatch("172.16.0.0/12", {f}) '
            'OR cidrmatch("192.168.0.0/16", {f}))')


def internal(field):
    return INTERNAL.format(f=field)


# Each detection:
#   title, uuid, finding (bool), domain, severity, mitre, kill_chain, description,
#   rule_title, search, risk (list), threats (list), suppress, nes, drill
DETECTIONS = [
    dict(
        key="D1", title="Kestrel - Phishing Email from Lookalike Domain Delivered",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a01", finding=True, domain="threat", severity="medium",
        mitre=["T1566.002"], kill_chain=["Delivery"],
        description="An email from a sender domain on the Kestrel threat list (lookalike or known phishing "
                    "infrastructure) was delivered to one or more mailboxes. Recipients are at risk of "
                    "credential harvesting.",
        rule_title="Phishing email \"$subject$\" from $src_user$ delivered to $recipient_count$ mailbox(es)",
        search=f"""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(All_Email.recipient) as recipient values(All_Email.subject) as subject values(All_Email.src) as src from datamodel=Email.All_Email where index=esdemo All_Email.action=delivered by All_Email.message_id All_Email.src_user
| `drop_dm_object_name("All_Email")`
| eval sender_domain=lower(mvindex(split(src_user, "@"), 1))
| lookup esdemo_threat_domains domain AS sender_domain OUTPUT threat_category, description AS threat_description
| where isnotnull(threat_category)
| eval recipient_count=mvcount(recipient), user=mvmap(recipient, lower(mvindex(split(recipient, "@"), 0)))
| table firstTime lastTime message_id subject src_user sender_domain src recipient recipient_count user threat_category threat_description""",
        risk=[("user", "user", 25)], threats=[("src_user", "email_address"), ("sender_domain", "domain")],
        entity=("src_user", "other", 25),
        risk_message="Phishing email from $src_user$ ($threat_category$) delivered to $user$",
        suppress="message_id", nes="message_id",
        drill=("View the delivered phishing email", 'index=esdemo sourcetype="esdemo:email" message_id="$message_id$"'),
    ),
    dict(
        key="D2", title="Kestrel - User Browsed to Known Phishing Domain",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a02", finding=False, domain="threat", severity="medium",
        mitre=["T1204.001"], kill_chain=["Exploitation"],
        description="A user's web traffic reached a domain on the Kestrel threat list. Produces an intermediate "
                    "finding (risk only) that feeds the finding-based detection.",
        rule_title="$user$ browsed to $url_domain$",
        search=f"""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method sum(Web.bytes_out) as bytes_out from datamodel=Web.Web where index=esdemo Web.action=allowed by Web.user Web.src Web.url_domain
| `drop_dm_object_name("Web")`
| lookup esdemo_threat_domains domain AS url_domain OUTPUT threat_category, description AS threat_description
| where isnotnull(threat_category)""",
        risk=[("user", "user", 30)], threats=[("url_domain", "domain"), ("url", "url")],
        risk_message="$user$ connected to $threat_category$ domain $url_domain$ ($http_method$)",
        suppress="user,url_domain", nes="user",
        drill=("View the web requests", 'index=esdemo sourcetype="esdemo:proxy" user="$user$" url_domain="$url_domain$"'),
    ),
    dict(
        key="D3", title="Kestrel - Successful Sign-in from External IP Address",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a03", finding=True, domain="access", severity="high",
        mitre=["T1078.004"], kill_chain=["Exploitation"],
        description="A Kestrel account signed in successfully from an IP address outside the corporate ranges. "
                    "Kestrel staff sign in from the office network or the corporate VPN, so this may indicate use "
                    "of stolen credentials.",
        rule_title="$user$ signed in to $app$ from external IP $src$",
        search=f"""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(Authentication.app) as app values(Authentication.authentication_method) as authentication_method values(Authentication.dest) as dest from datamodel=Authentication.Authentication where index=esdemo Authentication.action=success by Authentication.user Authentication.src
| `drop_dm_object_name("Authentication")`
| where NOT {internal("src")}""",
        risk=[("user", "user", 40)], threats=[("src", "ip_address")],
        risk_message="$user$ signed in to $app$ from external IP $src$",
        suppress="user,src", nes="user",
        drill=("View sign-ins for $user$", 'index=esdemo sourcetype="esdemo:auth" user="$user$"'),
    ),
    dict(
        key="D4", title="Kestrel - Encoded PowerShell Command Executed",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a04", finding=True, domain="endpoint", severity="high",
        mitre=["T1059.001"], kill_chain=["Installation"],
        description="PowerShell was started with an encoded command line (-enc / -EncodedCommand). Attackers "
                    "use this to hide payloads; administrators sometimes use it for scripted tasks. Decode the "
                    "command and review the parent process before deciding.",
        rule_title="Encoded PowerShell launched by $parent_process_name$ on $dest$ as $user$",
        search="""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where index=esdemo Processes.process_name IN ("powershell.exe", "pwsh.exe") (Processes.process="* -enc *" OR Processes.process="* -e *" OR Processes.process="* -ec *" OR Processes.process="*-EncodedCommand *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name("Processes")`""",
        risk=[("user", "user", 35), ("dest", "system", 35)],
        threats=[("parent_process_name", "process_name"), ("process_name", "process_name")],
        risk_message="Encoded PowerShell launched by $parent_process_name$ on $dest$ as $user$",
        suppress="dest,user", nes="user,dest",
        drill=("View process activity on $dest$", 'index=esdemo sourcetype="esdemo:endpoint:process" dest="$dest$"'),
    ),
    dict(
        key="D5", title="Kestrel - Password Spray Against Multiple Accounts",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a05", finding=True, domain="access", severity="medium",
        mitre=["T1110.003"], kill_chain=["Exploitation"],
        description="One source IP failed to sign in to 10 or more different Kestrel accounts within 20 minutes.",
        rule_title="Password spray from $src$ against $user_count$ accounts",
        search="""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime dc(Authentication.user) as user_count values(Authentication.user) as targeted_users values(Authentication.app) as app from datamodel=Authentication.Authentication where index=esdemo Authentication.action=failure by Authentication.src
| `drop_dm_object_name("Authentication")`
| where user_count >= 10""",
        risk=[("src", "system", 30)], threats=[("src", "ip_address")],
        risk_message="Password spray from $src$ against $user_count$ accounts",
        suppress="src", nes="src",
        drill=("View failed sign-ins from $src$", 'index=esdemo sourcetype="esdemo:auth" src="$src$"'),
    ),
    dict(
        key="D6", title="Kestrel - Successful Sign-in After Password Spray",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a06", finding=True, domain="access", severity="critical",
        mitre=["T1110.003", "T1078.004"], kill_chain=["Exploitation"],
        description="A source IP that failed against 10 or more accounts then signed in successfully. The "
                    "account that succeeded is very likely compromised.",
        rule_title="$user$ signed in from $src$ after a password spray against $failed_user_count$ accounts",
        search="""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(Authentication.app) as app from datamodel=Authentication.Authentication where index=esdemo Authentication.action IN ("success", "failure") by Authentication.src Authentication.user Authentication.action
| `drop_dm_object_name("Authentication")`
| eventstats dc(eval(if(action=="failure", user, null()))) as failed_user_count by src
| where action=="success" AND failed_user_count >= 10""",
        risk=[("user", "user", 50)], threats=[("src", "ip_address")],
        risk_message="$user$ signed in from $src$ after a password spray against $failed_user_count$ accounts",
        suppress="user,src", nes="user",
        drill=("View sign-ins from $src$", 'index=esdemo sourcetype="esdemo:auth" src="$src$"'),
    ),
    dict(
        key="D7", title="Kestrel - Remote Execution with PsExec",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a07", finding=True, domain="endpoint", severity="high",
        mitre=["T1569.002", "T1021.002"], kill_chain=["Actions on Objectives"],
        description="PsExec was used to run commands on other Kestrel hosts. Outside the IT team this is a "
                    "strong sign of lateral movement.",
        rule_title="$user$ used $process_name$ on $dest$ to run commands on $target_count$ remote host(s)",
        search=r"""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where index=esdemo Processes.process_name IN ("psexec.exe", "psexec64.exe", "PsExec.exe", "PsExec64.exe") by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name("Processes")`
| rex field=process max_match=10 "\\\\\\\\(?<target_host>[A-Za-z0-9\.\-]+)"
| eval target_host=mvdedup(target_host), target_count=mvcount(target_host)""",
        risk=[("user", "user", 45), ("dest", "system", 30)],
        threats=[("process_name", "process_name"), ("target_host", "hostname")],
        risk_message="$user$ used $process_name$ on $dest$ to reach $target_host$",
        suppress="user,dest", nes="user,dest",
        drill=("View PsExec activity", 'index=esdemo sourcetype="esdemo:endpoint:process" (process_name="PsExec*" OR process_name="PSEXESVC.exe")'),
    ),
    dict(
        key="D8", title="Kestrel - Account Created by Non-IT User",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a08", finding=True, domain="identity", severity="high",
        mitre=["T1136.002"], kill_chain=["Installation"],
        description="A domain account was created by a user who is not in the Kestrel IT administrators list. "
                    "Attackers create accounts to keep access.",
        rule_title="$src_user$ created account $object$ on $dest$",
        search="""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as command values(All_Changes.dest) as dest from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management index=esdemo All_Changes.action=created by All_Changes.object All_Changes.Account_Management.src_user
| rename All_Changes.Account_Management.src_user as src_user
| `drop_dm_object_name("All_Changes")`
| lookup esdemo_it_admins user AS src_user OUTPUT role AS admin_role
| where isnull(admin_role)""",
        risk=[("src_user", "user", 45)], threats=[("object", "user")],
        risk_message="$src_user$ (not an IT administrator) created account $object$",
        suppress="src_user,object", nes="src_user",
        drill=("View account changes by $src_user$", 'index=esdemo sourcetype="esdemo:change" src_user="$src_user$"'),
    ),
    dict(
        key="D9", title="Kestrel - Large Outbound Transfer to External Destination",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a09", finding=True, domain="network", severity="critical",
        mitre=["T1048"], kill_chain=["Actions on Objectives"],
        description="A Kestrel host sent more than 500 MB to a single external destination within 20 minutes.",
        rule_title="$src_host$ sent $mb_out$ MB to external $dest$",
        search=f"""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as bytes_out values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where index=esdemo All_Traffic.action=allowed by All_Traffic.src All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`
| where NOT {internal("dest")} AND bytes_out > 524288000
| lookup esdemo_assets ip AS src OUTPUT nt_host AS src_host
| eval src_host=coalesce(src_host, src), mb_out=round(bytes_out/1048576, 1)""",
        risk=[("src_host", "system", 60)], threats=[("dest", "ip_address")],
        risk_message="$src_host$ sent $mb_out$ MB to external $dest$",
        suppress="src,dest", nes="src_host",
        drill=("View traffic to $dest$", 'index=esdemo sourcetype="esdemo:firewall" dest="$dest$"'),
    ),
    dict(
        key="D10", title="Kestrel - Internal Network Scan Detected",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a10", finding=True, domain="network", severity="medium",
        mitre=["T1046"], kill_chain=["Reconnaissance"],
        description="One internal host connected to 20 or more hosts or 50 or more ports within 20 minutes. "
                    "Check whether the source is an approved scanner before escalating.",
        rule_title="$src_host$ scanned $dest_count$ hosts / $port_count$ ports",
        search="""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime dc(All_Traffic.dest) as dest_count dc(All_Traffic.dest_port) as port_count from datamodel=Network_Traffic.All_Traffic where index=esdemo by All_Traffic.src
| `drop_dm_object_name("All_Traffic")`
| where dest_count >= 20 OR port_count >= 50
| lookup esdemo_assets ip AS src OUTPUT nt_host AS src_host, category AS src_category
| eval src_host=coalesce(src_host, src)""",
        risk=[("src_host", "system", 20)], threats=[("src", "ip_address")],
        risk_message="$src_host$ scanned $dest_count$ hosts / $port_count$ ports",
        suppress="src", nes="src_host",
        drill=("View connections from $src$", 'index=esdemo sourcetype="esdemo:firewall" src="$src$"'),
    ),
    dict(
        key="D12", title="Kestrel - Password-Protected Archive Created",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a12", finding=False, domain="endpoint", severity="medium",
        mitre=["T1560.001"], kill_chain=["Actions on Objectives"],
        description="An archiving tool created a password-protected archive, a common data-staging step before "
                    "exfiltration. Produces an intermediate finding (risk only).",
        rule_title="$user$ created a password-protected archive on $dest$",
        search="""
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where index=esdemo Processes.process_name IN ("7z.exe", "7za.exe", "rar.exe", "winrar.exe") Processes.process="* -p*" by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name("Processes")`""",
        risk=[("user", "user", 25), ("dest", "system", 25)], threats=[("process_name", "process_name")],
        risk_message="$user$ created a password-protected archive on $dest$ with $process_name$",
        suppress="user,dest", nes="user,dest",
        drill=("View process activity on $dest$", 'index=esdemo sourcetype="esdemo:endpoint:process" dest="$dest$"'),
    ),
    dict(
        key="D11", title="Kestrel - [Fallback] Mailbox Rule Forwarding to External Address",
        uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9a11", finding=True, domain="threat", severity="high",
        mitre=["T1114.003"], kill_chain=["Actions on Objectives"], disabled=True,
        description="FALLBACK ONLY - this is the detection the Detection Builder Agent writes live in the demo. "
                    "Keep it disabled; enable it only if the live build is not possible. An Exchange Online inbox "
                    "rule forwards mail to an address outside kestrel.example.",
        rule_title="$user$ created inbox rule forwarding mail to $forward_to$",
        search=r"""
index=esdemo sourcetype="esdemo:o365:audit" Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| rex field=_raw max_match=5 "\"Name\":\s*\"(?:ForwardTo|ForwardAsAttachmentTo|RedirectTo)\",\s*\"Value\":\s*\"(?<forward_to>[^\"]+)\""
| where isnotnull(forward_to) AND NOT match(lower(forward_to), "@kestrel\.example$")
| eval user=lower(mvindex(split(UserId, "@"), 0))
| stats count min(_time) as firstTime max(_time) as lastTime values(forward_to) as forward_to values(Operation) as operation values(ClientIP) as src by user""",
        risk=[("user", "user", 50)], threats=[("forward_to", "email_address"), ("src", "ip_address")],
        risk_message="$user$ created an inbox rule forwarding mail to $forward_to$",
        suppress="user", nes="user",
        drill=("View mailbox audit events for $user$", 'index=esdemo sourcetype="esdemo:o365:audit" UserId="$user$@*"'),
    ),
]

FBD = dict(
    title="Kestrel - Multi-Stage Attack on Entity - Rule",
    label="Kestrel - Multi-Stage Attack on Entity",
    uuid="5b0f3c7e-8a52-4d0e-9a1f-1d3c2b7e9b01",
    description="Finding-based detection: groups the findings and intermediate findings of one entity into a "
                "finding group when they span 3 or more MITRE ATT&CK tactics from 6 or more different detections "
                "within the last 30 minutes. In the demo only the compromised finance user crosses this line.",
    where="mitre_tactic_id_count >= 3 AND source_count >= 6",
)


def risk_json(d):
    out = []
    for field, otype, score in d["risk"]:
        out.append({"risk_object_field": field, "risk_object_type": otype, "risk_score": score,
                    "risk_message": d["risk_message"]})
    for field, ttype in d["threats"]:
        out.append({"threat_object_field": field, "threat_object_type": ttype})
    return json.dumps(out, separators=(",", ":"))


def entities_json(d):
    """ES 8.7 creates one finding per entity listed here, so each detection names exactly one
    primary entity. Risk (intermediate findings) still goes to every object in d["risk"]."""
    f, t, s = d.get("entity") or d["risk"][0]
    return json.dumps([{"risk_object_field": f, "risk_object_type": t, "risk_score": s}], separators=(",", ":"))


def conf_value(text):
    """Multi-line conf values: continue lines with a trailing backslash."""
    lines = [l for l in textwrap.dedent(text).strip("\n").split("\n")]
    return " \\\n".join(lines)


def render_ebd(d):
    title = d["title"] + " - Rule"
    ann = {"analytic_story": [STORY], "mitre_attack": d["mitre"], "kill_chain_phases": d["kill_chain"],
           "type": "TTP"}
    meta = {"detection_id": d["uuid"], "detection_version": "1", "deprecated": "0"}
    drill_name, drill_search = d["drill"]
    drill = [{"name": drill_name, "search": drill_search,
              "earliest_offset": "$info_min_time$", "latest_offset": "$info_max_time$"}]
    kv = [
        ("action.correlationsearch.enabled", "1"),
        ("action.correlationsearch.detection_type", "ebd"),
        ("action.correlationsearch.label", d["title"]),
        ("action.correlationsearch.annotations", json.dumps(ann, separators=(",", ":"))),
        ("action.correlationsearch.metadata", json.dumps(meta, separators=(",", ":"))),
        ("description", d["description"]),
    ]
    if d["finding"]:
        kv += [
            ("action.notable", "1"),
            ("action.notable.param.rule_title", d["rule_title"]),
            ("action.notable.param.rule_description", d["description"]),
            ("action.notable.param.security_domain", d["domain"]),
            ("action.notable.param.severity", d["severity"]),
            ("action.notable.param.nes_fields", d["nes"]),
            ("action.notable.param.investigation_type", "default"),
            ("action.notable.param._entities", entities_json(d)),
            ("action.notable.param.extract_artifacts",
             json.dumps({"asset": ["src", "dest", "src_host"], "identity": ["user", "src_user"]},
                        separators=(",", ":"))),
            ("action.notable.param.drilldown_searches", json.dumps(drill, separators=(",", ":"))),
            ("action.notable.param.verbose", "0"),
        ]
    else:
        kv += [("action.notable", "0")]
    kv += [
        ("action.risk", "1"),
        ("action.risk.param._risk", risk_json(d)),
        ("action.risk.param._risk_message", d["risk_message"]),
        ("action.risk.param._risk_score", "0"),
        ("action.risk.param.verbose", "0"),
        ("alert.digest_mode", "1"),
        ("alert.suppress", "1"),
        ("alert.suppress.fields", d["suppress"]),
        ("alert.suppress.period", "1800s"),
        ("alert.track", "0"),
        ("counttype", "number of events"),
        ("relation", "greater than"),
        ("quantity", "0"),
        ("cron_schedule", "*/2 * * * *"),
        ("dispatch.earliest_time", "-20m"),
        ("dispatch.latest_time", "now"),
        ("enableSched", "1"),
        ("schedule_window", "0"),
        ("disabled", "1" if d.get("disabled") else "0"),
        ("search", conf_value(d["search"])),
    ]
    return title, kv


def render_fbd():
    t = FBD["title"]
    search = f"""
| tstats summariesonly=false `common_fbd_fields` from datamodel=Risk.All_Risk where (index=risk OR index=notable) by All_Risk.normalized_risk_object, All_Risk.risk_object_type, index
| `drop_dm_object_name("All_Risk")`
| `get_mitre_annotations`
| `generate_findings_summary_on_entity`
| where {FBD["where"]}"""
    drill_search = (f'| from datamodel Risk.All_Risk | search normalized_risk_object="$normalized_risk_object$" '
                    f'risk_object_type="$risk_object_type$" | `get_correlations` | table _time source risk_object '
                    f'risk_score risk_message annotations.mitre_attack.mitre_tactic')
    drill = [{"name": "View all findings for $normalized_risk_object$", "search": drill_search,
              "earliest_offset": "$info_min_time$", "latest_offset": "$info_max_time$"}]
    ann = {"analytic_story": [STORY], "type": "Correlation"}
    meta = {"detection_id": FBD["uuid"], "detection_version": "1", "deprecated": "0"}
    kv = [
        ("action.correlationsearch.enabled", "1"),
        ("action.correlationsearch.detection_type", "fbd"),
        ("action.correlationsearch.label", FBD["label"]),
        ("action.correlationsearch.annotations", json.dumps(ann, separators=(",", ":"))),
        ("action.correlationsearch.metadata", json.dumps(meta, separators=(",", ":"))),
        ("action.correlationsearch.fbd.input_type", "entity"),
        ("action.correlationsearch.fbd.search_on", '["int-finding","finding"]'),
        ("description", FBD["description"]),
        ("action.notable", "1"),
        ("action.notable.param.rule_title",
         "Multi-stage attack on $risk_object_type$ $normalized_risk_object$ ($mitre_tactic_id_count$ ATT&CK tactics, "
         "$source_count$ detections)"),
        ("action.notable.param.rule_description", FBD["description"]),
        ("action.notable.param.security_domain", "threat"),
        ("action.notable.param.severity", "critical"),
        ("action.notable.param.investigation_type", "default"),
        ("action.notable.param.extract_artifacts",
         '{"asset":["src","dest","dvc","orig_host","_risk_system"],"identity":["src_user","user","_risk_user"]}'),
        ("action.notable.param.drilldown_searches", json.dumps(drill, separators=(",", ":"))),
        ("action.notable.param.verbose", "0"),
        ("alert.digest_mode", "1"),
        ("alert.suppress", "1"),
        ("alert.suppress.fields", "normalized_risk_object,risk_object_type"),
        ("alert.suppress.period", "2400s"),
        ("alert.track", "0"),
        ("counttype", "number of events"),
        ("relation", "greater than"),
        ("quantity", "0"),
        ("cron_schedule", "*/3 * * * *"),
        ("dispatch.earliest_time", "-30m"),
        ("dispatch.latest_time", "now"),
        ("enableSched", "1"),
        ("schedule_window", "0"),
        ("disabled", "0"),
        ("search", conf_value(search)),
    ]
    return t, kv


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def main():
    parts = ["# Generated by build_content.py - edit the Python definitions, not this file.\n"]
    for d in DETECTIONS:
        title, kv = render_ebd(d)
        parts.append(f"\n[{title}]\n" + "\n".join(f"{k} = {v}" for k, v in kv) + "\n")
    title, kv = render_fbd()
    parts.append(f"\n[{title}]\n" + "\n".join(f"{k} = {v}" for k, v in kv) + "\n")
    write(os.path.join(APP, "default", "savedsearches.conf"), "".join(parts))

    write(os.path.join(APP, "default", "app.conf"), """[install]
state = enabled

[package]
id = DA-ESS-esdemo
check_for_updates = false

[id]
name = DA-ESS-esdemo
version = 1.0.2

[launcher]
author = ES Demo Build
description = Kestrel Systems ES 8 demo detections: 12 event-based detections, 1 finding-based detection, threat-domain and IT-admin lookups.
version = 1.0.2

[ui]
is_visible = false
label = ES Demo Detections (Kestrel Systems)
""")
    write(os.path.join(APP, "default", "transforms.conf"), """[esdemo_threat_domains]
filename = esdemo_threat_domains.csv
case_sensitive_match = false

[esdemo_it_admins]
filename = esdemo_it_admins.csv
case_sensitive_match = false
""")
    write(os.path.join(APP, "lookups", "esdemo_threat_domains.csv"),
          "domain,threat_category,description\n"
          "kestrel-hr-notices.example,phishing_sender,Lookalike Kestrel HR domain registered 2 days ago; sends credential-phishing email\n"
          "kestrel-sso-verify.example,credential_harvesting,Fake Kestrel single sign-on page that collects passwords\n"
          "cdn-update-check.example,malware_c2,Payload staging and command-and-control server\n"
          "mailbox-relay.example,exfiltration,Free mail relay used to receive forwarded mail\n")
    write(os.path.join(APP, "lookups", "esdemo_it_admins.csv"),
          "user,role\nrkumar,Senior Systems Administrator\negarcia,Network Engineer\njkim,Service Desk Analyst\n"
          "omensah,Security Analyst\ngsilva,DevOps Engineer\nsvc_backup,service_account\n")
    write(os.path.join(APP, "metadata", "default.meta"), """[]
access = read : [ * ], write : [ admin, sc_admin, ess_admin ]
export = system

[savedsearches]
owner = nobody
export = system

[lookups]
export = system

[transforms]
export = system
""")
    write(os.path.join(APP, "README.txt"), """DA-ESS-esdemo 1.0.0 - Kestrel Systems ES 8 demo detections

Install on the ES search head (Apps > Manage Apps > Install app from file).
Depends on TA-esdemo (field mappings, asset lookup) and data in index=esdemo.
All detections search index=esdemo only and are safe to leave enabled.
The [Fallback] mailbox-rule detection ships disabled on purpose.
""")
    print(f"wrote {len(DETECTIONS)} event-based + 1 finding-based detection to {APP}")


if __name__ == "__main__":
    main()
