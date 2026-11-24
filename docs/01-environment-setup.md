# Environment setup

How to build the Kestrel Systems ES 8 agentic demo on a Splunk Cloud stack, end to end. This is the configuration that was built and rehearsed. Where testing changed the original plan, the final settings are given, and the [AI agents guide](04-ai-agents-guide.md) and [Troubleshooting](05-troubleshooting.md) explain why.

The story is set at **Kestrel Systems**, a made-up mid-size company with offices in Singapore, Sydney and London and the domain `kestrel.example` (reserved for testing). Every user, host, domain and IP address is fictional; attacker infrastructure uses the IP ranges reserved for documentation.

Placeholders used throughout:

| Placeholder | Meaning | Example |
|---|---|---|
| `<stack>` | Splunk Cloud stack name | `mycompany` for `mycompany.splunkcloud.com` |
| `<es-sh>` | ES search head host | `es.<stack>.splunkcloud.com` |
| `<soar>` | SOAR Cloud tenant URL | `https://<tenant>.soar.splunkcloud.com` |

---

## Step 0: Prerequisites, and where to do each step

**Versions this was built and tested on:**

| Component | Version |
|---|---|
| Splunk Cloud Platform | 10.5 (Victoria) |
| Enterprise Security | 8.7.0, **Premier** edition (needed for the AI SOC analyst / Triage and Response agents) |
| Mission Control app | 6.7.0 |
| Splunk SOAR (Cloud) | 8.8.0, paired with ES |
| Laptop | Python 3.8+ (generator and test script use only the standard library; `truststore` is optional) |

**Agent availability.** Detection Builder, the AI SOC analyst (triage) and Guided Response are Splunk Cloud features gated by ES edition and region. Check that the AI assistant is turned on (**Configure → AI**) and that the agents appear before building the demo around them. Your Splunk account team can turn on agents that are missing.

**Which search head.** If the stack has a core search head and a separate ES search head:
- Indexes, HEC tokens and IP allow lists apply to the whole stack. Create them once, from either search head.
- Everything else (add-ons, CIM setup, asset and identity, detections, AI settings, response plans) goes on the **ES search head**.
- The core search head needs nothing, unless people will search the demo data there; then install `TA-esdemo` on it too.

**Pair SOAR with ES** (one-off, about 20 minutes):
1. Give `soar_user` to the ES roles that should map to SOAR: **Settings → Users and Authentication → Roles → `ess_analyst`** (and `ess_user`) **→ Capabilities**. (`ess_analyst` inherits it from `ess_user` on recent versions.)
2. Add SOAR Cloud's outbound IP to the stack's **Search head API access** IP allow list (**Settings → Server settings → IP allow list**). If SOAR Cloud has its own allow list, ask Splunk Support to add your stack's IP.
3. In ES: **Configure → All configurations → Splunk SOAR → Pairing → Start pairing**. Enter the SOAR base URL and a SOAR administrator's credentials, check the ES URL is `https://<es-sh>`, test, map roles (for example `mc_admin` → Automation engineer, `ess_analyst` → Incident commander, `ess_user` → Observer), and finish. Make sure a role you hold (for example `ess_admin`, which `sc_admin` inherits) is mapped, or you cannot run SOAR actions from ES.
4. Check the pairing page says paired. Pairing problems are logged in `index=_internal source=*mc_es_soar_pairing.log`.

---

## Step 1: Index, HEC token and CIM index list (about 10 minutes)

### 1a. Create the index
Go to **Settings → Indexes → New Index**.

| Field | Value |
|---|---|
| Index name | `esdemo` |
| Index data type | Events |
| Searchable retention | 30 days |

### 1b. Create the HEC token
Go to **Settings → Data inputs → HTTP Event Collector → New Token**.

| Field | Value |
|---|---|
| Name | `esdemo_hec` |
| Indexer acknowledgement | **Off** |
| Source type | Automatic (the generator sets the source type on each event) |
| Allowed indexes | `esdemo` |
| Default index | `esdemo` |

Copy the token value and keep it on your laptop only. Your HEC URL is `https://http-inputs-<stack>.splunkcloud.com`.

### 1c. Add `esdemo` to the CIM index list
Without this step the data models never see the demo data, and no detection will fire.

In ES, open **Configure → CIM Setup**. You can also reach it through the *Splunk Common Information Model* app's setup page. Add `esdemo` to **Indexes whitelist** for each of these data models:

- Authentication
- Change
- Email
- Endpoint
- Network Traffic
- Web

Then check that acceleration is enabled for those same six data models: **Settings → Data models → Edit → Edit acceleration**.

---

## Step 2: Install the add-on and lookups (about 15 minutes)

### 2a. Install the TA-esdemo add-on
Go to **Apps → Manage Apps → Install app from file**, choose `dist/TA-esdemo-1.0.0.spl` and select Upload. Splunk Cloud runs its automatic app checks (AppInspect) on upload.

The add-on contains:
- field extractions and CIM tags for the 7 `esdemo:*` sourcetypes;
- two lookup definitions: `esdemo_assets` (38 hosts) and `esdemo_identities` (30 users).

### 2b. Register the asset and identity lookups in ES
Go to **ES → Configure → All configurations → Assets and identities**.

1. **Asset lookups** tab → **New → New configuration**
   - Source: `esdemo_assets`
   - Name: `kestrel_assets`
   - Category: `kestrel`
   - Enable it.
2. **Identity lookups** tab → **New → New configuration**
   - Source: `esdemo_identities`
   - Name: `kestrel_identities`
   - Category: `kestrel`
   - Leave **Email** checked under conventions (it's on by default). ES 8.x has no separate Identity settings tab.
   - Enable it.
3. **Correlation setup** tab: check it's set to **Activate for all sourcetypes**. Correlation adds each host's and user's priority, department and watchlist status to findings, which the Triage agent needs.

ES merges the lookups in about 5 minutes. To check that they merged:

```
| inputlookup asset_lookup_by_str where nt_host="kes-*" | stats count
| inputlookup identity_lookup_expanded where identity="dchen" | table identity priority bunit category watchlist
```

### 2c. Send test events from your laptop
```bash
export ESDEMO_STACK=<stack>
export ESDEMO_HEC_TOKEN=<paste esdemo_hec token>
python3 tools/verify.py            # add --system-trust behind a TLS-inspecting corporate proxy
```
The script prints a run id like `verify-20261116-101500`. Check the events arrived:

```
index=esdemo esdemo_run="<run id>" | stats count by sourcetype, eventtype, tag
```

You should see 7 events. Six of them carry tags; `esdemo:o365:audit` carries none on purpose (see the note at the end). To confirm each data model sees its event, run `| tstats summariesonly=false count from datamodel=Authentication where index=esdemo` (and the same for Endpoint.Processes, Email, Web, Network_Traffic and Change).

**If something fails:**
- `timed out`: your laptop's public IP isn't on the **HEC access for ingestion** IP allow list (Settings → Server settings → IP allow list), or your network blocks port 443 to `http-inputs-<stack>.splunkcloud.com`.
- `CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain`: a corporate security proxy is re-signing TLS. Run `python3 -m pip install truststore` once, then `python3 verify.py --system-trust`. Alternatively, use `--ca-bundle <corporate root CA .pem>`.
- `HTTP 403`: the token is wrong or disabled.
- `HTTP 400 ... index`: `esdemo` isn't in the token's allowed indexes.

---

## Step 3: SOAR actions for Guided Response (about 20 minutes)

Guided Response recommends SOAR actions, and you run them from ES. For the actions to complete without errors, SOAR needs apps and assets set up to run them against. This step sets up two:

| SOAR asset | App | Used for | Touches real systems? |
|---|---|---|---|
| `kestrel_containment` | **Kestrel Demo Containment** (custom app in this package) | disable user, enable user, reset password, block ip, unblock ip, quarantine device, unquarantine device, block url, delete email | **No.** Every action is simulated. |
| `kestrel_splunk` | **Splunk** (built into SOAR) | run query (enrichment during the response) | Read-only searches on your stack |

All of Step 3 happens in **SOAR** (`<soar>`), except 3a and 3e, which happen on the **ES search head**.

### 3a. Make sure your own ES account can run SOAR actions (ES search head)
ES runs SOAR actions as the ES user who clicks the button. Your account has only the `sc_admin` role, which inherits `ess_admin`.

1. In ES, go to **Configure → All configurations → Splunk SOAR → Pairing** and look at **Configuration details**.
2. If neither `sc_admin` nor `ess_admin` is mapped, select **Edit role mapping** and add **`ess_admin` → Automation engineer**, then Save.
3. Leave the existing mappings in place. If you remove every mapping, ES and SOAR become unpaired.

### 3b. Install the Kestrel Demo Containment app (SOAR)
1. In SOAR, open the main menu → **Apps**.
2. Select **Install App** (top right) and upload `dist/kestreldemocontainment-1.0.2.tgz`. It declares Python 3.13, which SOAR 8.x requires.
3. Find **Kestrel Demo Containment** in the list of unconfigured apps.

If SOAR Cloud refuses custom app uploads on your tenant, open a Splunk Support ticket to enable it. As a fallback, Guided Response can be shown with the Splunk app's `run query` actions only.

### 3c. Configure the containment asset (SOAR)
On the Kestrel Demo Containment app, select **Configure New Asset**.

| Tab | Field | Value |
|---|---|---|
| Asset Info | Asset name | `kestrel_containment` (the response plans in Step 4 refer to this name) |
| | Description | Simulated containment for the ES demo |
| Asset Settings | hec_url | *(optional, see below)* `https://http-inputs-<stack>.splunkcloud.com` |
| | hec_token | *(optional)* the `esdemo_hec` token |
| | hec_index | `esdemo` |
| | verify_ssl | checked |
| | simulate_failure_for | *(optional)* e.g. `kes-dc01`. Any action against that target fails, which lets you show how a failed action looks in ES. |
| Approval Settings | | No approval. Guided Response already asks the analyst before running an action. |
| Access Control | | Leave the default (all roles), so the users mapped from ES can use it. |

Select **Save**, then **Test Connectivity**. It should say *Test Connectivity Passed*.

**Optional HEC logging.** When `hec_url` and `hec_token` are set, each action also writes an `esdemo:containment` event to Splunk. That lets you show in the demo that "the account really was disabled":
```
index=esdemo sourcetype="esdemo:containment" | table _time action target state change_id comment
```
For this to work, SOAR Cloud's outbound IP must be on the **HEC access for ingestion** allow list. That's the same IP you added to the Search head API access list for pairing. If Test Connectivity reports `HEC logging is configured but failed`, that allow-list entry is missing. Leave the HEC fields empty if you don't need this; the actions still succeed.

### 3d. Configure the Splunk enrichment asset (SOAR)
1. Create a Splunk token for SOAR to use, on the **ES search head**:
   - **Settings → Users → New User**: `svc_soar_demo`, with role `ess_analyst`.
   - Then **Settings → Tokens → New Token**: user `svc_soar_demo`, audience `soar`, expiry 90 days.
2. In SOAR, go to **Apps** → search **Splunk** → **Configure New Asset**.

| Tab | Field | Value |
|---|---|---|
| Asset Info | Asset name | `kestrel_splunk` |
| Asset Settings | Device (server) | `<es-sh>` |
| | Port | `8089` |
| | API token | the token from step 1 |
| | Verify server certificate | checked |
| Ingest Settings | | Leave polling **off**. This asset is only for running actions. |

Select **Save → Test Connectivity**. If it times out, SOAR's IP isn't on the **Search head API access** allow list. It should already be there from pairing.

### 3e. Configure the AI SOC analyst (ES search head)
In ES 8.7 the Triage agent's settings page is **AI SOC analyst** (**Configure → All configurations → AI SOC analyst**, or **Configure → AI**).

1. **Allowed actions** (top of the page):
   - *Start investigations from findings when identified as…*: leave **unticked** for a presenter-led demo, where you promote findings live. Tick it with **True Positive** only to show the fully autonomous flow, in which the agent promotes a finding and then works through the response plan.
   - *Resolve findings when identified as…*: leave **unticked**, otherwise it can close the harmless look-alikes before you show its verdicts.
2. **Connectors** tab. For each connector, set the default SOAR asset, switch AI usage on, and set each action to **Run** (no approval) or **Ask for approval**:

| Connector | Default asset | AI usage | Actions |
|---|---|---|---|
| **Splunk** | `kestrel_splunk` | Active | `run query`: Run |
| **Kestrel Demo Containment** | `kestrel_containment` | Active | `disable user`, `reset password`, `block ip`, `quarantine device`, `block url`: **Run** for the autonomous demo, or **Ask for approval** for a guided demo. Keep `unblock ip`, `unquarantine device`, `delete email` and `reset demo state` on **Ask for approval**. |
| Everything else | — | Inactive | — |

3. **Detections** tab: done in Step 4c.

### 3f. Check that it works
1. In SOAR, create an empty event: **Home → Sources/Events → New Event**. In the *Add events* dialog, set Event Name to `Step 3 test`, leave Label as `events`, and select **SAVE**. This dialog only creates the event; you run the actions in the next step.
2. Open **Step 3 test** and select **Action** (lightning-bolt icon, top right).
3. Search for **disable user**, choose app **Kestrel Demo Containment** and asset `kestrel_containment`, set username to `jkim` and comment to `step3-test`, then select **Launch**.
4. The result appears in the event's activity or action results panel: "Disabled user jkim on Kestrel IdP", with a `CHG-…` change ID.
5. Run **enable user** on `jkim` the same way, to undo it.
6. Run **run query** on `kestrel_splunk` with `index=esdemo | stats count by sourcetype`. You should get the 7 test sourcetypes.
7. Close the test event.

If you turned on HEC logging, check: `index=esdemo sourcetype="esdemo:containment" | table _time action target state change_id`.

The full test from ES (Guided Response recommending and running these actions on a real investigation) happens in Step 4, once the first findings exist.

---

## Step 4: Detections, AI SOC analyst, response plans and a rehearsal (about 45 minutes)

Everything in Step 4 happens on the **ES search head**, except 4e (your laptop). Files:

| File | What it is |
|---|---|
| `dist/DA-ESS-esdemo-1.0.2.spl` | The demo detections app (13 detections and 2 lookups). It passes Splunk Cloud's AppInspect checks with no failures. |
| `generator/esdemo.py` | The live data generator: normal activity, attack scenarios, and the 50-incident cap |
| `docs/02-demo-runbook.md` | The 30-minute demo script |

### What the detections do

| # | Detection | Type | Fires on (one full demo run) |
|---|---|---|---|
| D1 | Phishing Email from Lookalike Domain Delivered | event-based, finding | 1: the email to `dchen`, `mwong` and `pnair` |
| D2 | User Browsed to Known Phishing Domain | event-based, risk only | `dchen` (intermediate finding) |
| D3 | Successful Sign-in from External IP Address | event-based, finding | 2: `dchen`, and `slee` |
| D4 | Encoded PowerShell Command Executed | event-based, finding | 2: `dchen` (malicious), and `rkumar` (harmless admin script) |
| D5 | Password Spray Against Multiple Accounts | event-based, finding | 1: from `198.51.100.77` |
| D6 | Successful Sign-in After Password Spray | event-based, finding | 1: `slee` |
| D7 | Remote Execution with PsExec | event-based, finding | 1: `dchen` on `kes-ws-fin-001` |
| D8 | Account Created by Non-IT User | event-based, finding | 1: `dchen` created `svc_sqlbackup2` |
| D9 | Large Outbound Transfer to External Destination | event-based, finding | 1: `kes-sql01` → `203.0.113.99`, about 900 MB |
| D10 | Internal Network Scan Detected | event-based, finding | 1: `kes-vulnscan01` (the approved scanner, so harmless) |
| D12 | Password-Protected Archive Created | event-based, risk only | `dchen` on `kes-sql01` (intermediate finding) |
| D11 | [Fallback] Mailbox Rule Forwarding to External Address | event-based, **ships disabled** | Only if you can't build it live with Detection Builder |
| FBD | Multi-Stage Attack on Entity | **finding-based** | 1: a finding group on `dchen` (7 detections, 7 ATT&CK tactics) |

That's **12 findings per run**, or 13 if you build the mailbox-forwarding detection live.

`tests/sim_detections.py` replays 40 minutes of generator output through Python versions of these detections: normal activity alone produces 0 findings, and a full demo produces exactly the findings above. The rehearsal on the real stack matched.

Timing:
- The event-based detections run every 2 minutes, look back 20 minutes, and fire once per entity per 30 minutes.
- The finding-based detection runs every 3 minutes over the last 30 minutes, and fires once per entity per 40 minutes.
- Leave **at least 40 minutes between full runs**, or the second run gets suppressed.

### 4a. Install the detections app
1. Go to **Apps → Manage Apps → Install app from file** and upload `dist/DA-ESS-esdemo-1.0.2.spl`. All detections are shared globally (`export = system`), which the ES Detections page needs in order to list them.
2. In ES, go to **Security content → Detections** (or **Content management**) and filter on `Kestrel`. You should see 13 detections, with 12 enabled and `[Fallback]` disabled.

### 4b. Turn off the two built-in risk rules during the demo
Before the demo, the stack had exactly two detections enabled:
- **Risk - 24 Hour Risk Threshold Exceeded - Rule**
- **Risk - 7 Day ATT&CK Tactic Threshold Exceeded - Rule**

Both would also fire on `dchen`, but 10–20 minutes late. Disable them so the incident count stays predictable and the finding group comes from the Kestrel finding-based detection. You can turn them back on afterwards.

### 4c. Switch the AI SOC analyst on for the demo detections, and give each a response plan
Go to **AI SOC analyst → Detections** tab:
1. Turn it on for D1, D3, D4, D5, D6, D7, D8, D9 and D10 (the Kestrel detections that create findings). Leave it off for **Multi-Stage Attack on Entity**: finding groups and intermediate findings are not triaged.
2. Open each detection's **agent guidance** and select its preferred response plan (after 4d, once the plans exist):

| Detection | Preferred response plan |
|---|---|
| Encoded PowerShell Command Executed | Kestrel - Account Compromise |
| Successful Sign-in After Password Spray | Kestrel - Account Compromise |
| Password Spray Against Multiple Accounts | Kestrel - Account Compromise |
| Phishing Email from Lookalike Domain Delivered | Kestrel - Suspicious Email (optional) |

If you delete and recreate a plan, select it again here. The guidance stores the plan's ID, and a deleted plan leaves new investigations with **no plan attached**.

Verdicts arrive a few minutes after each finding. The agent triages up to 10 new findings per detection run; see the [AI agents guide](04-ai-agents-guide.md).

### 4d. Create the two response plans
Go to **Security content → Response plans** and create both from the Splunk templates. Three rules learned in testing:
- **Attach actions without fixed parameters.** Add the SOAR action to the task and leave its fields empty; the agent fills them in from the investigation.
- **Every action chip must point at a configured app** (Kestrel Demo Containment or Splunk). The templates come with actions for VirusTotal, Splunk Attack Analyzer, CrowdStrike, Recorded Future, Talos and others. Remove those, or the agent recommends actions that cannot run.
- **Task descriptions are instructions to the agent.** Write them unconditionally. A template description such as *"If the business risk is deemed acceptable, disable the account…"* makes the Response agent stop and wait for a business decision, even when the action is set to **Run**.

Each investigation keeps its own copy of the plan, made when the plan was attached. After editing a plan, publish it again and re-attach it, or test on a new investigation.

**Plan 1: `Kestrel - Account Compromise`** (from the **Account Compromise** template; final structure)

| Phase | Task | Description (exact wording matters) | SOAR action |
|---|---|---|---|
| Detection and Analysis | Review the user's recent sign-ins and activity | A check on the user's recent activities. | `run query` on `kestrel_splunk`: `index=esdemo (user=$user$ OR src_user=$user$) earliest=-60m \| stats count by sourcetype action` |
| Containment, Eradication, and Recovery | Disable account | Pre-approved containment. When the investigation is a confirmed true positive, disable the affected user account immediately with the disable user action. Business-impact review is not required; the incident commander has pre-authorised account disablement for confirmed compromises. Do not ask for confirmation. | `disable user` on `kestrel_containment` |
| Containment, Eradication, and Recovery | Force a password reset and revoke sessions | Pre-approved. After the account is disabled, reset the same user's password and revoke all sessions with the reset password action. Do not ask for confirmation. | `reset password` on `kestrel_containment` |

Optional extra containment tasks, written the same way: **Block the attacker IP addresses** (`block ip`) and **Isolate the affected workstation** (`quarantine device`).

**Plan 2: `Kestrel - Suspicious Email`** (from the **Suspicious Email** template)
- Keep the template's Ingestion, Internal Hunting and Notification tasks as checklist items, with their action chips removed. Delete the **Longer-running analysis jobs** phase, and the *Hunt network activity* and *Hunt file executions* tasks.
- In **Enforcement and increased monitoring**:

| Task | SOAR action |
|---|---|
| Purge the message from all mailboxes | `delete email` on `kestrel_containment` |
| Block the phishing URL and domain | `block url` on `kestrel_containment` |
| Reset the password of anyone who clicked | `reset password` on `kestrel_containment` |

Switch **Published** on for both plans.

### 4e. Rehearsal run (from your laptop)
```bash
cd generator
export ESDEMO_HEC_TOKEN=<esdemo_hec token>
export ESDEMO_STACK=<stack>
python3 esdemo.py list                           # what each scenario does and the findings it creates
python3 esdemo.py demo --system-trust            # baseline + all 4 scenarios over ~3 minutes; leave running
```
Leave it running (the normal activity keeps the dashboards alive) and watch ES:

| After | You should see |
|---|---|
| about 3–5 minutes | event-based findings D1, D3, D4, D5, D6 and D10 in the analyst queue |
| about 6–8 minutes | D7, D8 and D9, then the **Multi-Stage Attack on Entity** finding group on `dchen` |
| about 10–15 minutes | AI SOC analyst verdicts on the findings: malicious for `dchen` and `slee`, harmless for `rkumar` and `kes-vulnscan01` |

Check what fired:
```
index=notable earliest=-30m source="Kestrel*" | stats count by source
index=risk earliest=-30m source="Kestrel*" | stats count sum(risk_score) as risk by risk_object
```
Expected: 12 findings (11 event-based plus 1 finding group), and `dchen` at roughly 275 risk.

Then test Guided Response on the rehearsal:
1. Promote the `dchen` finding group to an investigation.
2. Apply **Kestrel - Account Compromise**.
3. In the AI assistant, use the prompts in the [runbook](02-demo-runbook.md): name the plan explicitly, and run one action per prompt.
4. Check it in `index=esdemo sourcetype="esdemo:containment"`.

### 4f. Reset between runs
1. In the ES analyst queue, filter to the `Kestrel - *` detections, select everything from the rehearsal, and **close** it, along with its investigations. The disposition can be "Closed - Rehearsal" or similar.
2. In SOAR, run the **reset demo state** action on asset `kestrel_containment` from any event. It undoes every simulated change (accounts re-enabled, IPs and URLs unblocked, devices released), so the next run doesn't answer "already disabled".
3. On your laptop, run `python3 esdemo.py reset-budget`. This resets the generator's own count of how many incidents have been used, not ES. `python3 esdemo.py status` shows the count, plus a search to compare with the real number in ES.
4. Wait at least **40 minutes** after the previous run before starting the next one. Otherwise suppression from the previous run hides the new findings.

How the 50-incident cap works:
- Each `demo` run reserves 14: 12 findings plus 2 for the detection you build live and the investigation you promote.
- The generator refuses to start a run that would take the total over 50 (`--cap` changes the limit).
- That covers a rehearsal, the live demo and one spare run before you need to reset.

### 4g. Practise the Detection Builder segment
The mailbox-forwarding rule (`esdemo:o365:audit`, `New-InboxRule` with an external `ForwardTo`) has no detection on purpose. Build it with the Detection Builder Agent using the two prompts in the runbook, then check the settings the agent chose before saving. Its defaults don't suit a live demo:

| Agent default | Set to |
|---|---|
| Hourly (`0 * * * *`) | `*/2 * * * *` |
| `-70m@m` to `-10m@m` | `-20m` to `now` |
| No throttling | Throttle on `user` for 30 minutes |
| Risk score 1 | 50 |
| `$user$` in the detection **name** | A plain name; keep `$user$` in the finding title only |

After practising, delete or disable the detection you built, so you can build it again live. The shipped `Kestrel - [Fallback] Mailbox Rule Forwarding to External Address` stays disabled unless the live build fails.

---

## Data each sourcetype carries

| Sourcetype | CIM data model | Key fields |
|---|---|---|
| `esdemo:auth` | Authentication | action, app, user, src, dest, authentication_method, signature, signature_id, reason |
| `esdemo:endpoint:process` | Endpoint.Processes | dest, user, process, process_name, process_path, process_id, process_guid, parent_process(_name/_id/_path), original_file_name, process_hash |
| `esdemo:email` | Email | action, src_user, recipient, subject, message_id, src, file_name, url, signature |
| `esdemo:proxy` | Web.Proxy | action, src, user, url, url_domain, dest, http_method, status, bytes_in, bytes_out, category, http_user_agent |
| `esdemo:firewall` | Network_Traffic | action, src, src_port, dest, dest_port, transport, app, bytes_in, bytes_out, direction, rule |
| `esdemo:change` | Change.Account_Management | action, change_type, object_category, object, user, src_user, dest, command, signature_id, result |
| `esdemo:o365:audit` | *(none, on purpose)* | CreationTime, Workload, Operation, UserId, ClientIP, Parameters{}, ResultStatus |

`esdemo:o365:audit` is left out of every data model on purpose. It holds the inbox forwarding rule that no detection covers yet, so in the demo the Detection Builder Agent writes that detection live.

## People and hosts the scenarios use

| Role in scenario | User | Host |
|---|---|---|
| Phishing victim → lateral movement → data exfiltration | `dchen` (Finance Manager, high priority) | `kes-ws-fin-001` → `kes-fs01`, `kes-sql01` |
| Password spray, then a successful login | `slee` (Account Executive, Sydney) | `kes-ws-sales-001` |
| Look-alike that's harmless: admin PowerShell | `rkumar` (Senior Systems Administrator) | `kes-ws-it-001`, `kes-jump01` |
| Look-alike that's harmless: vulnerability scanner | `svc_vulnscan` | `kes-vulnscan01` |
| Executive on the watchlist (phishing recipient) | `mwong` (CFO, critical priority) | `kes-lt-exec-001` |

Attacker infrastructure uses the IP ranges reserved for documentation (203.0.113.0/24 and 198.51.100.0/24), so no real address appears in the demo.

To rename the company, edit the constants at the top of `tools/build_lookups.py` and run `./scripts/package.sh`. It regenerates the lookups, copies them to `generator/data/`, and repackages every app.
