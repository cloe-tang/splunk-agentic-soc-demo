# Design reference

How the demo environment is put together, and why. For setup steps, see the [setup guide](01-environment-setup.md).

## Architecture

```
 Laptop                                  Splunk Cloud stack                                    SOAR Cloud
 ───────                                 ──────────────────                                    ──────────
 generator/esdemo.py ──HEC (443)──►  index=esdemo  (7 sourcetypes, JSON, CIM field names)
   baseline noise                          │  TA-esdemo: eventtypes + tags → CIM data models
   4 attack scenarios                      ▼
   50-incident budget                Authentication · Endpoint.Processes · Email · Web
                                     Network_Traffic · Change.Account_Management
                                           │  (searched with summariesonly=false)
                                           ▼
                                     DA-ESS-esdemo: 11 event-based detections (every 2 min)
                                           │  findings → index=notable   risk → index=risk
                                           ▼
                                     Finding-based detection (every 3 min, Risk data model)
                                           │  finding group on the compromised user
                                           ▼
                                     AI SOC analyst: triage verdicts on findings
                                     Response plans + agent ─────────── run action ──────►  Kestrel Demo Containment
                                                                                             (simulated, stateful)
                                     index=esdemo sourcetype=esdemo:containment ◄── HEC ───  logs every change
```

## Components

| Path | What it is | Installed on |
|---|---|---|
| `TA-esdemo/` | Search-time add-on: JSON extraction, CIM EVALs and aliases, eventtypes and tags for 6 sourcetypes, and asset and identity lookups (38 hosts, 30 users) | ES search head |
| `content/DA-ESS-esdemo/` | ES content app: 12 event-based detections (one disabled fallback), 1 finding-based detection, threat-domain and IT-admin lookups | ES search head |
| `soar/kestreldemocontainment/` | SOAR app: 9 simulated containment actions, `test connectivity` and `reset demo state`; optional HEC logging | SOAR |
| `generator/esdemo.py` | Live data generator: baseline, scenarios, demo timeline, incident budget | Your laptop |
| `tools/verify.py` | Sends one test event per sourcetype | Your laptop |
| `tools/build_lookups.py`, `content/build_content.py`, `soar/build_app_json.py` | Generate the lookups, `savedsearches.conf` and the SOAR app metadata from Python definitions | Build only |
| `tests/` | Offline detection simulation, and SOAR app unit tests with a stand-in SOAR runtime | Build only |

## Data model

All events arrive through HEC `/services/collector/event` as JSON with CIM field names, so the add-on only needs JSON extraction, a few EVALs and the tags.

| Sourcetype | CIM data model | Key fields |
|---|---|---|
| `esdemo:auth` | Authentication | action, app, user, src, dest, authentication_method, signature, signature_id, reason |
| `esdemo:endpoint:process` | Endpoint.Processes | dest, user, process, process_name, process_path, process_id, process_guid, parent_process(_name/_id/_path), original_file_name, process_hash |
| `esdemo:email` | Email | action, src_user, recipient, subject, message_id, src, file_name, url, signature |
| `esdemo:proxy` | Web.Proxy | action, src, user, url, url_domain, dest, http_method, status, bytes_in, bytes_out, category |
| `esdemo:firewall` | Network_Traffic | action, src, src_port, dest, dest_port, transport, app, bytes_in, bytes_out, direction, rule |
| `esdemo:change` | Change.Account_Management | action, change_type, object_category, object, user, src_user, dest, command, signature_id, result |
| `esdemo:o365:audit` | *(none, on purpose)* | CreationTime, Workload, Operation, UserId, ClientIP, Parameters{} |
| `esdemo:containment` | *(none)* | action, target, state, previous_state, change_id, result (written by the SOAR app) |

`esdemo:o365:audit` stays out of every data model so the Detection Builder Agent has a real gap to fill.

Each event carries `ingest_batch` (the generator's run id) and a realistic `source` (for example `kestrel:edr:process`). Events carry **no scenario labels**: the AI SOC analyst reads raw events, and in the first rehearsal it cited a label (`esdemo_scenario=benign`) as evidence.

## Scenarios

| Scenario | What happens | Findings |
|---|---|---|
| `phishing` | Lookalike-domain payroll email to `dchen`, `mwong` and `pnair`; `dchen` clicks and submits credentials; the attacker signs in as `dchen` from `203.0.113.45` and adds an inbox rule forwarding to an external address; a macro document launches hidden encoded PowerShell that downloads a script | 3 (+1 once the Detection Builder detection exists) |
| `spray` | `198.51.100.77` fails against 18 accounts, then signs in as `slee` with password only (she normally uses MFA) | 3 |
| `benign` | `rkumar` (IT admin) runs an encoded PowerShell AD-inventory export from PowerShell ISE; the approved scanner `kes-vulnscan01` sweeps 26 hosts on 10 ports | 2 |
| `lateral` | `dchen` runs discovery commands, PsExec to `kes-fs01` and `kes-sql01`, creates `svc_sqlbackup2`, makes a password-protected archive on `kes-sql01`, and sends about 900 MB to `203.0.113.99` | 3 + 1 finding group |

`demo` plays them at +0s, +45s, +90s and +150s, alongside baseline noise (about 2 events per second).

## Detections

| # | Detection | Output | Entity | Risk (score) | MITRE |
|---|---|---|---|---|---|
| D1 | Phishing Email from Lookalike Domain Delivered | finding | sender | each recipient (25) | T1566.002 |
| D2 | User Browsed to Known Phishing Domain | risk only | — | user (30) | T1204.001 |
| D3 | Successful Sign-in from External IP Address | finding | user | user (40) | T1078.004 |
| D4 | Encoded PowerShell Command Executed | finding | user | user (35), host (35) | T1059.001 |
| D5 | Password Spray Against Multiple Accounts | finding | source IP | source (30) | T1110.003 |
| D6 | Successful Sign-in After Password Spray | finding | user | user (50) | T1110.003, T1078.004 |
| D7 | Remote Execution with PsExec | finding | user | user (45), host (30) | T1569.002, T1021.002 |
| D8 | Account Created by Non-IT User | finding | creator | creator (45) | T1136.002 |
| D9 | Large Outbound Transfer to External Destination | finding | source host | host (60) | T1048 |
| D10 | Internal Network Scan Detected | finding | source host | host (20) | T1046 |
| D12 | Password-Protected Archive Created | risk only | — | user (25), host (25) | T1560.001 |
| D11 | [Fallback] Mailbox Rule Forwarding to External Address | finding, **disabled** | user | user (50) | T1114.003 |
| FBD | Multi-Stage Attack on Entity | finding group | risk object | — | ≥3 tactics from ≥6 detections in 30 min |

**Timing and suppression**

| | Schedule | Window | Suppression |
|---|---|---|---|
| Event-based | `*/2 * * * *` | `-20m` to `now` | 30 min per entity |
| Finding-based | `*/3 * * * *` | `-30m` to `now` | 40 min per risk object |

Leave at least 40 minutes between full runs, or suppression hides the second run.

**Why the finding-based detection doesn't use ES's built-in finding-group window.** ES 8.7's finding-group templates (`generate_time_range`) keep a per-detection window in a lookup, and after an idle period advance it only one `max_append_time` step per run. Deployed a day before a demo, such a detection can stay blind for the first 15–30 minutes. A plain rolling window avoids this, and the `generate_findings_summary_on_entity` macros still produce a proper finding group.

**Why each detection names one entity.** ES 8.7 creates a separate finding for every entity listed in `action.notable.param._entities`. Listing user and host produced two findings per event (17 instead of 12 in the first rehearsal). Each detection now names one primary entity, and still adds risk to every object in `action.risk.param._risk`.

**Why only `dchen` gets a finding group.** `dchen` collects risk from 7 detections (D1, D2, D3, D4, D7, D8, D12) across 7 tactics. `slee` gets 2 detections, and each host gets at most 2, below the threshold of 6. The threshold is crossed only after the lateral-movement detections land, so the group contains the whole chain.

## Incident budget

The generator keeps a ledger in `~/.esdemo_budget.json`. Each `demo` run reserves 14: 12 findings, plus 2 for the detection built live and an investigation you promote. It refuses a run that would go over the cap (default 50, `--cap` to change). `status` shows the ledger; `reset-budget` clears it after you close the findings in ES.

## Fictional data

| Item | Value |
|---|---|
| Company / domain | Kestrel Systems / `kestrel.example` (RFC 2606 reserved) |
| Attacker IPs | `203.0.113.0/24`, `198.51.100.0/24` (documentation ranges) |
| "SaaS" IPs | `192.0.2.0/24` |
| Attacker domains | `kestrel-hr-notices.example`, `kestrel-sso-verify.example`, `cdn-update-check.example`, `mailbox-relay.example` |

To rebrand: edit the constants in `tools/build_lookups.py`, then run `./scripts/package.sh`.
