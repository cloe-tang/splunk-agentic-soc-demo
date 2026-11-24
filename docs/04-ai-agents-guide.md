# AI agents guide

How the ES 8.7 agents behaved in this environment, and what it takes to get good results from each. Where a point comes from observation rather than Splunk documentation, it says so.

## Detection Builder Agent

**Ask in two steps.** The agent configures a detection's output (finding, risk, MITRE) only after the name, description and SPL exist. One prompt asking for both makes it stop and ask for those fields.

1. Write the search:
   > Write SPL for a detection that finds Exchange Online inbox rules forwarding mail to an address outside our company. Data is in index=esdemo sourcetype=esdemo:o365:audit. Operations are New-InboxRule or Set-InboxRule. The forwarding address is in Parameters{}.Value where Parameters{}.Name is ForwardTo, RedirectTo or ForwardAsAttachmentTo. Our domain is kestrel.example. Return user (from UserId), the forwarding address and ClientIP. Also suggest a detection name and description.
2. Configure the output:
   > Configure a finding for this detection with risk score 50 on the user, the forwarding address and ClientIP as threat objects, and MITRE ATT&CK T1114.003. Run it every 2 minutes over the last 20 minutes and throttle by user for 30 minutes.

**Check its defaults before saving.** Left alone, it created a detection that ran hourly over `-70m@m` to `-10m@m`, without throttling, with risk score 1 and `$user$` in the detection name. That detection would not have produced a finding during a 30-minute demo. Its SPL (using `mvzip` of `Parameters{}.Name` and `Parameters{}.Value`) was correct.

## AI SOC analyst (Triage agent)

**What it analyses**
- Findings from the detections it is turned on for, a few minutes after they are created. Verdicts arrived 2–10 minutes after each finding in rehearsal.
- Not finding groups and not intermediate findings (risk-only events). Splunk's documentation says so for 8.8, and 8.7 behaved the same way.

**Limits (dispatch settings in `es_ai_settings.conf`)**

| Setting | Value | Meaning |
|---|---|---|
| `max_findings_per_detection_run` | 10 | Each run of a detection sends at most 10 of its new findings |
| `max_findings_per_run` / `batch_size` | 10 | Findings per analysis cycle |
| `queue_age_limit_hours` | 2 | Findings waiting longer are skipped |
| `max_findings_per_24h` | 200 | Daily cap for the stack |

Splunk documents that only the first 10 findings of each detection run are triaged, but doesn't say how "first" is chosen. The best reading is the order the run creates them, which follows the search's result order. The limit counts findings, not entities. To make sure the important ones are triaged:
- end busy detections with `| sort 0 - risk_score`;
- list one entity per finding;
- throttle per entity;
- or run the detection more often.

**How it uses risk-based alerting.** It pulls the finding entity's risk events as a *Risk Event Timeline* and uses them as context, not proof. It confirms its verdict with its own SPL searches, and weighs several hypotheses with likelihoods. In rehearsal the same detection (encoded PowerShell) came out:
- **True Positive, 95%** for `dchen`, whose timeline showed phishing and a visit to a credential-harvesting site;
- **Benign, 87%** for `rkumar`, who had no risk history, an IT-admin role, an ISE parent process, and a decoded AD-inventory command.

**Keep the data honest.** It reads raw events. Any label that gives away the answer (a field like `scenario=benign`) gets cited as evidence. Generated data must carry only what a real log would.

## Guided Response and the Response agent

**On-demand (guided).** From an investigation's AI assistant, or the Automation page's agentic chat:
- **Name the plan, phase and entities.** "What is the recommended response plan?" makes the agent choose a plan. "What response actions are there?" can be read as "what has already been recorded", and answered from the triage record ("no response plan").
- **It runs one SOAR action per turn.** Follow up with "Next, run … for …". To run several actions with one approval, put them in a SOAR playbook and attach the playbook to a task.
- **It may pass parameters as lists** (`['slee']`). The containment app accepts lists, stringified lists and comma-separated values.

**Autonomous (Response agent)**
- The plan comes from each detection's *agent guidance* (**AI SOC analyst → Detections**, preferred response plan). The agent works through the plan's tasks on investigations whose findings have AI triage results.
- Action policies (**Connectors** tab) decide *Run* or *Ask for approval* for each action.
- **Task descriptions override Run.** The template wording *"If the business risk is deemed acceptable, disable the account…"* made the agent stop with *"Requirement UNMET: no decision recorded on whether business risk allows disabling dchen"*, even though `disable user` was set to Run. Unconditional wording ("Pre-approved containment… Do not ask for confirmation") fixed it.
- **Investigations keep their own copy of the plan.** Edits to a plan reach only investigations it is attached to afterwards. Re-attach the plan to test a change.
- **Agent guidance stores the plan ID.** Recreating a plan leaves detections pointing at an ID that no longer exists, and their investigations get no plan at all.

**Response plans in general**
- Attach actions without fixed parameters; the agent fills them in.
- Remove action chips for apps you haven't configured. Templates include many.
