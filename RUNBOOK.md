# ES 8 Demo Runbook: 30 Minutes

**Story:** Kestrel Systems' finance manager Daniel Chen (`dchen`) falls for a payroll phish. The attacker signs in with his password, hides a mail-forwarding rule, runs a macro payload, moves to the file and SQL servers, creates a backdoor account and sends about 900 MB of finance data out. At the same time, someone password-sprays the single sign-on service and gets into Sarah Lee's (`slee`) account. Two harmless look-alikes go off too: an IT admin's encoded PowerShell script, and the approved vulnerability scanner.

---

## Before the session

| When | Do |
|---|---|
| Day before | Do the full rehearsal (SETUP.md 4e), check Guided Response works, then reset (4f). |
| **T-60 min** | **Safety-net run:** `python3 esdemo.py demo --system-trust --exit-after 600`. It produces a complete set of findings, AI verdicts and a finding group that you can fall back on if anything is slow live. Leave those findings open. |
| T-15 min | Check that at least 40 minutes have passed since the safety-net run started. Open these tabs: **Analyst queue** (filtered to `Kestrel`), **Detections**, **Response plans**, and a Search tab. On your laptop, `cd generator`, export the token and `python3 esdemo.py status`. |
| T-5 min | In the analyst queue, change the time filter to "Last 15 minutes" so only the live run will show. You can widen it again if you need the safety net. |

---

## The 30 minutes

### 0:00–2:00 · Set the scene, then start the attack
- **Say:** "This is Kestrel Systems: 38 hosts and 30 people across Singapore, Sydney and London, with data streaming into ES right now. I'm going to start a live attack and we'll watch ES and its AI agents handle it."
- **Do:** run `python3 esdemo.py demo --system-trust` and leave it running. The whole attack chain takes about 3 minutes to send.
- **Show:** in a Search tab, `index=esdemo | timechart span=10s count by sourcetype` to show the data arriving live.

### 2:00–8:00 · Detection Builder Agent (while ES works in the background)
- **Say:** "While the detections run, a detection engineer finds a gap. Attackers often hide a mailbox rule that forwards mail outside the company. Nothing covers that yet, so I'll ask the agent to write the detection."
- **Do:** go to **Detections → Create detection → Event-based**, open the AI assistant panel, and paste:
  > Create a detection that finds Exchange Online inbox rules that forward mail to an address outside our company. The data is in index=esdemo, sourcetype=esdemo:o365:audit. Operations are New-InboxRule or Set-InboxRule. The forwarding address is in Parameters{}.Value where Parameters{}.Name is ForwardTo, RedirectTo or ForwardAsAttachmentTo. Our domain is kestrel.example. Return the user (from UserId), the forwarding address and ClientIP. Create a finding with risk score 50 on the user and map it to MITRE T1114.003.
- **Show:** the SPL the agent writes, its explanation, and the test results. The test should find `dchen` forwarding to `finance-archive@mailbox-relay.example` from `203.0.113.45`. Accept the agent's suggestions, set the schedule to every 2 minutes, and **enable** it.
- **If it struggles:** ask it to "use spath on Parameters{} and mvzip Name and Value". If it still fails, enable **Kestrel - [Fallback] Mailbox Rule Forwarding to External Address** and explain it as "here's the one the agent produced in rehearsal".

### 8:00–13:00 · Event-based detections
- **Go to:** **Analyst queue**, filtered to Kestrel. By now about 9 findings should be in.
- **Show:**
  - **Phishing email delivered:** one finding covering 3 recipients. Each recipient got risk added, and the CFO (`mwong`) is on the watchlist.
  - **Successful sign-in from external IP** for `dchen` from `203.0.113.45`. Open it and point out the asset and identity details: Finance, high priority.
  - **Password spray**, followed by **Successful sign-in after password spray** for `slee`.
  - **Encoded PowerShell**, which appears twice: once for `dchen` launched by `winword.exe`, once for `rkumar` launched by `powershell_ise.exe`. **Say:** "Same detection, two very different stories. Hold that thought for triage."
- **Point out:** each detection also adds risk to the user and host, including the risk-only ones you don't see in the queue (browsing to the phishing domain, the password-protected archive).

### 13:00–18:00 · Finding-based detection
- **Show:** **Multi-Stage Attack on Entity**, a finding group on `dchen`. Open it: 7 or 8 detections across 7 ATT&CK tactics, from initial access through persistence and lateral movement to collection. That includes the detection you built 10 minutes ago.
- **Say:** "Instead of an analyst reading a dozen separate alerts, ES groups everything that happened to one person into a single finding group."
- **Do:** promote the finding group to an **investigation**. You'll use it in the Guided Response segment.

### 18:00–24:00 · Triage agent (AI SOC analyst)
- **Show:** the AI analysis on these findings:
  - `dchen`'s encoded PowerShell: expect **malicious**. The rationale should mention the Office parent process, the hidden window, the download from an external domain, and the earlier phishing.
  - `rkumar`'s encoded PowerShell: expect **benign**. It's an IT administrator on an admin workstation, the decoded command is an AD inventory export to an internal share, and the parent is an interactive ISE session.
  - `kes-vulnscan01`'s network scan: expect **benign**. The host is categorised as the vulnerability scanner, and it's the approved scanning account.
  - `slee`'s sign-in after the spray: expect **malicious** or **suspicious**.
- **Say:** "It suggests a disposition, explains why, and recommends next steps, but it hasn't closed or escalated anything on its own. We set it up that way: the analyst decides."
- **If verdicts aren't there yet:** widen the time filter and show the same findings from the safety-net run.

### 24:00–29:00 · Guided response plan
- **Go to:** the `dchen` investigation and apply the **Kestrel - Account Compromise** response plan.
- **Show:** the Guided Response agent recommending actions from the plan: **disable user dchen**, **reset password**, **quarantine device kes-ws-fin-001**, **block ip 203.0.113.45 / 203.0.113.99**.
- **Do:** approve **disable user dchen** and **quarantine device kes-ws-fin-001**. The results come back from SOAR with change IDs.
- **Prove it:** run `index=esdemo sourcetype="esdemo:containment" | table _time action target state change_id`.
- **Optional:** set `simulate_failure_for` on the asset to a host before the session, to show how a failed action looks and how the agent responds.

### 29:00–30:00 · Wrap up
- **Say:** "In 30 minutes: a detection built in plain language, event-based and finding-based detections, AI triage with explained verdicts, and containment guided by a response plan, all on live data."
- **Do:** stop the generator with Ctrl-C.

---

## After the session
1. Close the demo findings and investigations (SETUP.md 4f), then run `python3 esdemo.py reset-budget`.
2. Leave the new mailbox-forwarding detection in place for next time, or delete it to repeat the Detection Builder segment.
3. Turn the two built-in risk rules back on if this stack needs them.

## Quick fixes during the demo

| Symptom | Fix |
|---|---|
| No findings after 5 minutes | Run `index=esdemo esdemo_scenario=phishing \| stats count by sourcetype`. If that returns nothing, the generator isn't reaching HEC: check the laptop's IP on the HEC allow list and use `--system-trust`. If it does return events, check that the Kestrel detections are enabled. |
| Generator says the incident budget is exceeded | Close the old findings, then run `reset-budget`. In an emergency, run `--force`. |
| Findings appear, but there's no finding group | The finding-based detection runs every 3 minutes and needs the lateral-movement findings. Wait one more cycle, or use the safety-net group. |
| Guided Response shows no actions | Check the response plan tasks have SOAR actions on `kestrel_containment`, and that your role is mapped to SOAR (SETUP.md 3a). |
