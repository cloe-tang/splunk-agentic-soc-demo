# Splunk ES 8 agentic SOC demo: Kestrel Systems

A self-contained demo environment for **Splunk Enterprise Security 8.7** on Splunk Cloud, with **Splunk SOAR**. It streams simulated, fully fictional security data, so ES and its AI agents have something realistic to work on, and you control exactly when the attack happens.

It demonstrates:

| Capability | How the demo shows it |
|---|---|
| **Detection Builder Agent** | A deliberate detection gap (an inbox rule forwarding mail externally) that the agent writes a detection for, live |
| **Event-based detections** | 11 Kestrel detections across email, web, sign-in, endpoint, account and network data |
| **Finding-based detection** | A finding group on the compromised user when 6+ detections across 3+ ATT&CK tactics hit one entity |
| **Triage agent (AI SOC analyst)** | Verdicts with reasoning, including two look-alikes the agent correctly calls benign |
| **Guided response plans** | Response plans whose tasks carry SOAR actions, run step by step (guided) or automatically (Response agent) |

One full run produces **12 findings** (13 with the live-built detection). A built-in budget keeps the total under **50 incidents**. The whole session fits in **30 minutes** ([runbook](docs/02-demo-runbook.md)).

## Repository layout

```
├── README.md
├── docs/
│   ├── 01-environment-setup.md   step-by-step build: indexes, HEC, apps, A&I, SOAR, AI settings, response plans
│   ├── 02-demo-runbook.md        the 30-minute script, prompts and fallbacks
│   ├── 03-design-reference.md    architecture, data model, scenarios, detections, timing
│   ├── 04-ai-agents-guide.md     how each ES agent behaves and how to prompt or configure it
│   └── 05-troubleshooting.md     every issue hit while building, with fixes
├── dist/                         prebuilt packages, ready to upload
│   ├── TA-esdemo-1.0.0.spl
│   ├── DA-ESS-esdemo-1.0.2.spl
│   └── kestreldemocontainment-1.0.2.tgz
├── TA-esdemo/                    Splunk add-on source (CIM mappings + Kestrel lookups)
├── content/
│   ├── DA-ESS-esdemo/            ES detections app source (generated)
│   └── build_content.py          detection definitions → savedsearches.conf
├── soar/
│   ├── kestreldemocontainment/   SOAR app source (simulated containment)
│   └── build_app_json.py         SOAR app metadata generator
├── generator/
│   ├── esdemo.py                 live data generator (baseline, scenarios, budget)
│   └── data/                     copy of the asset and identity lookups
├── tools/
│   ├── build_lookups.py          generates the Kestrel company (users, hosts, IPs)
│   └── verify.py                 sends one test event per sourcetype
├── tests/
│   ├── sim_detections.py         replays generator output through the detection logic
│   ├── test_soar_app.py          SOAR app unit tests (stand-in runtime + mock HEC)
│   └── phantom_stub/             minimal stand-in for SOAR's phantom module
└── scripts/package.sh            rebuild everything into dist/
```

## Quick start

1. **Prerequisites:** Splunk Cloud with ES 8.7 Premier, the AI assistant and agents turned on, SOAR Cloud paired with ES, and Python 3.8+ on your laptop. See [setup, Step 0](docs/01-environment-setup.md#step-0-prerequisites-and-where-to-do-each-step).
2. **Build it:** follow the [setup guide](docs/01-environment-setup.md), Steps 1–4 (about 2 hours the first time). It uses the packages in `dist/`.
3. **Run it:**
   ```bash
   cd generator
   export ESDEMO_STACK=<stack>              # mycompany for mycompany.splunkcloud.com
   export ESDEMO_HEC_TOKEN=<token>          # never commit this
   python3 esdemo.py list                   # scenarios and the findings each creates
   python3 esdemo.py demo --system-trust    # --system-trust only behind a TLS-inspecting proxy
   ```
4. **Present it** with the [runbook](docs/02-demo-runbook.md). Between runs: close the findings, run **reset demo state** in SOAR, run `python3 esdemo.py reset-budget`, and wait 40 minutes.

## Rebuild and test

```bash
./scripts/package.sh            # regenerate lookups, detections and SOAR metadata, then package into dist/
./scripts/package.sh --inspect  # also run Splunk AppInspect cloud checks (pip install splunk-appinspect)
python3 tests/sim_detections.py # expect: RESULT: PASS (0 baseline findings, 12 per run, 1 finding group)
python3 tests/test_soar_app.py  # expect: FAILS 0
```

The generator and `verify.py` need only the Python standard library (`truststore` is optional, for `--system-trust`).

## Versions

| Package | Version | Notes |
|---|---|---|
| TA-esdemo | 1.0.0 | Passes AppInspect cloud checks (1 expected warning: private IPs in the asset lookup) |
| DA-ESS-esdemo | 1.0.2 | 1.0.1 shared detections globally; 1.0.2 uses one entity per finding. 1 expected warning: frequent schedules |
| Kestrel Demo Containment (SOAR) | 1.0.2 | 1.0.1 targeted Python 3.13; 1.0.2 accepts list parameters and adds *reset demo state* |
| Built and tested on | Splunk Cloud 10.5, ES 8.7.0, Mission Control 6.7.0, SOAR Cloud 8.8.0 | |

## Notes

- **All data is fictional.** It uses the `kestrel.example` domain and documentation-only IP ranges. Nothing touches real systems; the SOAR actions are simulated.
- **No secrets are stored here.** Pass the HEC token through `ESDEMO_HEC_TOKEN`. `.gitignore` excludes `.env`, `local/` and anything named `*token*`.
- **Keep the repository private** if your docs or commits mention your stack name, SOAR tenant or customer.
