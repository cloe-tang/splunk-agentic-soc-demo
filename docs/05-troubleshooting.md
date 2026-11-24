# Troubleshooting

Every problem hit while building and rehearsing this environment, with the cause and the fix.

## Data ingestion

| Symptom | Cause | Fix |
|---|---|---|
| `verify.py`: `cannot reach … timed out` | Laptop's public IP not on the stack's **HEC access for ingestion** allow list (another data source had already restricted it) | **Settings → Server settings → IP allow list**: add the laptop's IP as `/32`, and the IP of any network you'll present from. Check with `curl https://http-inputs-<stack>.splunkcloud.com/services/collector/health`. |
| `CERTIFICATE_VERIFY_FAILED … self-signed certificate in certificate chain` | A corporate security proxy (TLS inspection) re-signs HTTPS | `python3 -m pip install truststore`, then add `--system-trust` (uses the OS certificate store). Or `--ca-bundle <corporate root CA .pem>`. |
| `unrecognized arguments: --system-trust` | An old copy of `verify.py` | Use the version in `tools/`. |
| `HTTP 403` / `HTTP 400 … index` | Wrong token / `esdemo` not in the token's allowed indexes | Fix the token settings. |
| No events in a data model | `esdemo` missing from the CIM index list | ES **CIM Setup**: add `esdemo` to Authentication, Change, Email, Endpoint, Network Traffic and Web. |
| `ERROR: set ESDEMO_STACK` | The generator no longer hard-codes a stack | `export ESDEMO_STACK=<stack>`, or pass `--stack` / `--url`. |

## Splunk apps

| Symptom | Cause | Fix |
|---|---|---|
| Detections installed but not listed in ES | Saved searches shared at app level (`export = none`) | `metadata/default.meta`: `[savedsearches] export = system` (fixed in DA-ESS-esdemo 1.0.1). |
| AppInspect failure on upgrade | `[id] version` and `[launcher] version` differ | Keep both versions in `app.conf` equal. |
| AppInspect warning: frequent schedule | Detections run every 2–3 minutes | Expected for a live demo. |
| AppInspect warning: private IPs | Asset lookup contains internal IPs | Expected. |

## Detections

| Symptom | Cause | Fix |
|---|---|---|
| 17 findings instead of 12 | ES 8.7 makes one finding per entity in `_entities` | One primary entity per detection (DA-ESS-esdemo 1.0.2). |
| Finding-based detection late or silent after idle time | ES finding-group window (`generate_time_range`) advances one step per run | Plain rolling window (as shipped). |
| Built-in risk rules fire on `dchen` 10–20 minutes late | `latest=-10m` and accelerated summaries | Disable both during the demo (setup 4b). |
| Second run produces no findings | Suppression from the previous run (30 or 40 minutes) | Wait 40 minutes between runs. |
| Detection Builder detection never fires | Agent defaults: hourly, `-70m@m` to `-10m@m` | Set `*/2`, `-20m`, throttle on user (setup 4g). |

## AI SOC analyst

| Symptom | Cause | Fix |
|---|---|---|
| Verdict cites "benign tagging" | Generator put scenario labels in events | Labels removed (current `esdemo.py`). |
| "No SOAR enrichment executed" | Splunk connector's AI usage off | **AI SOC analyst → Connectors**: Splunk active, asset `kestrel_splunk`. |

## SOAR and response

| Symptom | Cause | Fix |
|---|---|---|
| SOAR: *incompatible Python version … Supported versions: ['3.13']* | App declared `"python_version": "3"` (read as 3.9) | Declare `"3.13"` (app 1.0.1 and later). |
| SOAR **Action** button does nothing | Event open in **Summary** view (that button only filters the timeline) | Switch the view to **Analyst**, then **Action**. |
| *Disabled user ['slee']* | Guided Response passes parameters as a list | App 1.0.2 parses lists. |
| *already disabled; no change made* in a new run | The app remembers state | Run **reset demo state** on `kestrel_containment` between runs. |
| *There is no recorded response action for this investigation* | Prompt read as "what has been recorded" | Name the plan and phase, and ask for recommendations (see the runbook). |
| *I am waiting for clarification … whether business risk makes it acceptable to disable dchen* | Conditional template wording in the task description | Rewrite the task descriptions as pre-approved, publish, and re-attach the plan. |
| Edited plan has no effect | Investigation holds its own copy of the old plan | Remove and re-attach the plan, or use a new investigation. |
| Investigations for some detections have no plan | Agent guidance points at a deleted plan ID | Select the plan again in **AI SOC analyst → Detections**. |
| Agent runs one action at a time | 8.7 behaviour | Prompt for each action, or use a SOAR playbook. |
