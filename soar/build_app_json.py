#!/usr/bin/env python3
"""Generate kestreldemocontainment.json (SOAR app metadata) so the action
definitions, parameters and outputs stay consistent with the connector."""
import json
import os

APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kestreldemocontainment")

# action name -> (identifier, type, description, param name, contains, undo)
ACTIONS = [
    ("disable user", "disable_user", "contain", "Disable a user account in the Kestrel directory (simulated)", "username", ["user name"], "enable user"),
    ("enable user", "enable_user", "correct", "Re-enable a user account in the Kestrel directory (simulated)", "username", ["user name"], "disable user"),
    ("reset password", "reset_password", "contain", "Force a password reset and revoke active sessions for a user (simulated)", "username", ["user name"], None),
    ("block ip", "block_ip", "contain", "Block an IP address at the Kestrel perimeter firewall (simulated)", "ip", ["ip"], "unblock ip"),
    ("unblock ip", "unblock_ip", "correct", "Remove an IP address block from the Kestrel perimeter firewall (simulated)", "ip", ["ip"], "block ip"),
    ("quarantine device", "quarantine_device", "contain", "Network-isolate an endpoint through Kestrel EDR (simulated)", "hostname", ["host name"], "unquarantine device"),
    ("unquarantine device", "unquarantine_device", "correct", "Release an endpoint from network isolation (simulated)", "hostname", ["host name"], "quarantine device"),
    ("block url", "block_url", "contain", "Add a URL or domain to the Kestrel web proxy block list (simulated)", "url", ["url", "domain"], None),
    ("delete email", "delete_email", "correct", "Purge a message from all Kestrel mailboxes by message ID (simulated)", "message_id", ["internet message id"], None),
]

PARAM_DESC = {
    "username": "User name, e.g. dchen or dchen@kestrel.example",
    "ip": "IPv4 address to block or unblock",
    "hostname": "Host name of the endpoint, e.g. kes-ws-fin-001",
    "url": "URL or domain",
    "message_id": "Internet message ID of the email",
}


def action_def(name, ident, atype, desc, pname, contains, undo):
    out = [
        {"data_path": "action_result.status", "data_type": "string", "example_values": ["success", "failed"]},
        {"data_path": f"action_result.parameter.{pname}", "data_type": "string", "contains": contains,
         "column_name": pname.replace("_", " ").title(), "column_order": 0},
        {"data_path": "action_result.parameter.comment", "data_type": "string"},
        {"data_path": "action_result.data.*.target", "data_type": "string", "contains": contains},
        {"data_path": "action_result.data.*.state", "data_type": "string", "column_name": "State", "column_order": 1},
        {"data_path": "action_result.data.*.previous_state", "data_type": "string"},
        {"data_path": "action_result.data.*.change_id", "data_type": "string", "column_name": "Change ID", "column_order": 2},
        {"data_path": "action_result.data.*.simulated", "data_type": "boolean"},
        {"data_path": "action_result.data.*.timestamp", "data_type": "string"},
        {"data_path": "action_result.summary.state", "data_type": "string"},
        {"data_path": "action_result.summary.change_id", "data_type": "string"},
        {"data_path": "action_result.message", "data_type": "string"},
        {"data_path": "summary.total_objects", "data_type": "numeric"},
        {"data_path": "summary.total_objects_successful", "data_type": "numeric"},
    ]
    d = {
        "action": name,
        "identifier": ident,
        "description": desc,
        "verbose": "Simulated action for demos. Records the change in the app state and, if HEC is configured, "
                   "sends an esdemo:containment event to Splunk. No real system is touched.",
        "type": atype,
        "read_only": False,
        "parameters": {
            pname: {"description": PARAM_DESC[pname], "data_type": "string", "required": True,
                    "primary": True, "contains": contains, "order": 0},
            "comment": {"description": "Reason or ticket reference", "data_type": "string",
                        "required": False, "order": 1},
        },
        "output": out,
        "render": {"type": "table"},
        "versions": "EQ(*)",
    }
    if undo:
        d["undo"] = undo
    return d


def main():
    app = {
        "appid": "481b6e93-d695-46b4-b689-5e6e2a0c20bb",
        "name": "Kestrel Demo Containment",
        "description": "Simulated containment actions (identity, firewall, EDR, proxy, mail) for the Kestrel Systems "
                       "ES 8 demo. Every action is a no-op against real systems: it returns a realistic result, keeps "
                       "track of state, and can log the change to Splunk via HEC.",
        "type": "generic",
        "product_vendor": "Kestrel Systems",
        "product_name": "Kestrel Demo Containment",
        "product_version_regex": ".*",
        "publisher": "ES Demo Build",
        "license": "Copyright (c) 2026 ES Demo Build. Demo use only.",
        "app_version": "1.0.2",
        "utctime_updated": "2026-11-17T05:45:00.000000Z",
        "package_name": "phantom_kestreldemocontainment",
        "main_module": "kestreldemocontainment_connector.py",
        "min_phantom_version": "6.2.1",
        "python_version": "3.13",
        "fips_compliant": False,
        "logo": "logo_kestrel.svg",
        "logo_dark": "logo_kestrel_dark.svg",
        "app_wizard_version": "1.0.0",
        "configuration": {
            "hec_url": {"description": "Optional: Splunk HEC base URL, e.g. https://http-inputs-<stack>.splunkcloud.com",
                        "data_type": "string", "required": False, "order": 0},
            "hec_token": {"description": "Optional: HEC token (esdemo_hec)", "data_type": "password",
                          "required": False, "order": 1},
            "hec_index": {"description": "Index for containment events", "data_type": "string",
                          "required": False, "default": "esdemo", "order": 2},
            "verify_ssl": {"description": "Verify the HEC TLS certificate", "data_type": "boolean",
                           "required": False, "default": True, "order": 3},
            "simulate_failure_for": {"description": "Optional: comma-separated targets that should fail "
                                                    "(to demo error handling), e.g. kes-dc01",
                                     "data_type": "string", "required": False, "order": 4},
        },
        "actions": [{
            "action": "test connectivity",
            "identifier": "test_connectivity",
            "description": "Validate the asset configuration (and HEC, if configured)",
            "type": "test",
            "read_only": True,
            "parameters": {},
            "output": [],
            "versions": "EQ(*)",
        }, {
            "action": "reset demo state",
            "identifier": "reset_demo_state",
            "description": "Undo every simulated change (run between demo runs)",
            "verbose": "Clears the app's remembered state: all users enabled, IPs and URLs unblocked, devices released, "
                       "emails restored. Logs a reset_demo_state event to Splunk if HEC is configured.",
            "type": "correct",
            "read_only": False,
            "parameters": {},
            "output": [{"data_path": "action_result.status", "data_type": "string"},
                       {"data_path": "action_result.message", "data_type": "string"},
                       {"data_path": "action_result.summary.cleared", "data_type": "numeric"}],
            "versions": "EQ(*)",
        }] + [action_def(*a) for a in ACTIONS],
    }
    path = os.path.join(APP_DIR, "kestreldemocontainment.json")
    with open(path, "w") as f:
        json.dump(app, f, indent=4)
        f.write("\n")
    print(f"wrote {path}: {len(app['actions'])} actions")


if __name__ == "__main__":
    main()
