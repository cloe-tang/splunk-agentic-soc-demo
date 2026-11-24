# Kestrel Demo Containment - simulated SOAR connector for the ES 8 demo.
#
# Every action is a no-op against real systems. It validates input, tracks the
# target's state in the app state file (so "block ip" twice says "already
# blocked"), returns realistic result data, and optionally writes an
# esdemo:containment event to Splunk HEC so the change shows up in searches.
import ast
import json
import re
import time
import uuid
from datetime import datetime, timezone

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# action identifier -> (state key, new state, "already" state, verb for messages)
ACTION_MAP = {
    "disable_user":        ("users",   "disabled",    "disabled",    "Disabled user"),
    "enable_user":         ("users",   "enabled",     "enabled",     "Enabled user"),
    "reset_password":      ("users",   "password_reset", None,       "Reset password and revoked sessions for"),
    "block_ip":            ("ips",     "blocked",     "blocked",     "Blocked IP"),
    "unblock_ip":          ("ips",     "allowed",     "allowed",     "Unblocked IP"),
    "quarantine_device":   ("devices", "quarantined", "quarantined", "Quarantined device"),
    "unquarantine_device": ("devices", "released",    "released",    "Released device"),
    "block_url":           ("urls",    "blocked",     "blocked",     "Blocked URL"),
    "delete_email":        ("emails",  "purged",      "purged",      "Purged email"),
}
PARAM_FOR = {
    "disable_user": "username", "enable_user": "username", "reset_password": "username",
    "block_ip": "ip", "unblock_ip": "ip",
    "quarantine_device": "hostname", "unquarantine_device": "hostname",
    "block_url": "url", "delete_email": "message_id",
}
DEFAULT_STATE = {"users": "enabled", "ips": "allowed", "devices": "released",
                 "urls": "allowed", "emails": "delivered"}
IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
SYSTEM_FOR = {"users": "Kestrel IdP", "ips": "Kestrel Firewall", "devices": "Kestrel EDR",
              "urls": "Kestrel Web Proxy", "emails": "Kestrel Mail Gateway"}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _targets(raw):
    """Guided Response may send a parameter as a list, a stringified list ("['slee']"),
    or a comma-separated string. Return a clean list of target strings."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        text = str(raw).strip()
        items = None
        if text.startswith("[") and text.endswith("]"):
            for parser in (json.loads, ast.literal_eval):
                try:
                    parsed = parser(text)
                    if isinstance(parsed, (list, tuple)):
                        items = list(parsed)
                        break
                except (ValueError, SyntaxError):
                    pass
        if items is None:
            items = text.split(",")
    out = []
    for i in items:
        i = str(i).strip().strip("'\"").strip()
        if i and i not in out:
            out.append(i)
    return out


def _normalize(kind, value):
    value = (value or "").strip().strip("<>") if kind == "emails" else (value or "").strip()
    if kind == "users":
        value = value.split("\\")[-1]          # KESTREL\dchen -> dchen
        value = value.split("@")[0].lower()    # dchen@kestrel.example -> dchen
    elif kind in ("devices", "urls"):
        value = value.lower()
    return value


class KestrelDemoContainmentConnector(BaseConnector):

    def __init__(self):
        super().__init__()
        self._state = {}
        self._config = {}

    # ------------------------------------------------------------ lifecycle
    def initialize(self):
        self._state = self.load_state() or {}
        for k in DEFAULT_STATE:
            self._state.setdefault(k, {})
        self._config = self.get_config() or {}
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    # ------------------------------------------------------------ helpers
    def _failure_targets(self):
        raw = self._config.get("simulate_failure_for") or ""
        return {t.strip().lower() for t in raw.split(",") if t.strip()}

    def _send_hec(self, event):
        url = (self._config.get("hec_url") or "").strip().rstrip("/")
        token = self._config.get("hec_token")
        if not url or not token:
            return None
        if not url.endswith("/services/collector/event"):
            url += "/services/collector/event"
        payload = {"time": time.time(), "host": "kestrel-soar", "source": "kestrel_demo_containment",
                   "sourcetype": "esdemo:containment",
                   "index": self._config.get("hec_index") or "esdemo", "event": event}
        try:
            r = requests.post(url, data=json.dumps(payload), timeout=15,
                              headers={"Authorization": f"Splunk {token}"},
                              verify=self._config.get("verify_ssl", True))
            return r.status_code
        except Exception as e:  # HEC logging is best effort and must never fail the action
            self.debug_print(f"HEC send failed: {e}")
            return f"error: {e}"

    # ------------------------------------------------------------ actions
    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Kestrel Demo Containment is a simulated connector; no remote system to reach.")
        if self._config.get("hec_url") and self._config.get("hec_token"):
            status = self._send_hec({"action": "test_connectivity", "result": "success", "simulated": True,
                                     "timestamp": _now()})
            if status != 200:
                self.save_progress(f"HEC test failed: {status}")
                return action_result.set_status(phantom.APP_ERROR, f"HEC logging is configured but failed: {status}")
            self.save_progress("HEC logging OK")
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reset(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        counts = {k: len(v) for k, v in self._state.items() if isinstance(v, dict)}
        for k in DEFAULT_STATE:
            self._state[k] = {}
        msg = "Demo state reset: every user enabled, IP/URL unblocked, device released, email restored " \
              f"(cleared {sum(counts.values())} tracked changes)"
        action_result.add_data({"cleared": counts, "simulated": True, "timestamp": _now()})
        action_result.update_summary({"cleared": sum(counts.values())})
        self._send_hec({"action": "reset_demo_state", "result": "success", "message": msg, "simulated": True,
                        "timestamp": _now()})
        self.save_progress(msg)
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_change(self, action_id, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        kind, new_state, already, verb = ACTION_MAP[action_id]
        pname = PARAM_FOR[action_id]
        raw = param.get(pname)
        targets = [_normalize(kind, t) for t in _targets(raw)]
        targets = [t for t in targets if t]

        if not targets:
            return action_result.set_status(phantom.APP_ERROR, f"Missing required parameter '{pname}'")
        if kind == "ips":
            bad = [t for t in targets if not IPV4.match(t)]
            if bad:
                return action_result.set_status(phantom.APP_ERROR, f"Not a valid IPv4 address: {', '.join(bad)}")

        messages, failed = [], []
        for target in targets:
            if target in self._failure_targets():
                msg = f"{SYSTEM_FOR[kind]} rejected the request for {target} (simulated failure)"
                self._send_hec({"action": action_id, "target": target, "result": "failure", "message": msg,
                                "simulated": True, "timestamp": _now()})
                failed.append(msg)
                continue
            previous = self._state[kind].get(target, DEFAULT_STATE[kind])
            change_id = "CHG-" + uuid.uuid4().hex[:8].upper()
            if already and previous == already:
                message = f"{target} is already {already}; no change made"
                state = previous
            else:
                self._state[kind][target] = new_state
                state = new_state
                message = f"{verb} {target} on {SYSTEM_FOR[kind]}"
            data = {"target": target, "state": state, "previous_state": previous, "change_id": change_id,
                    "system": SYSTEM_FOR[kind], "simulated": True, "timestamp": _now(),
                    "comment": param.get("comment", "")}
            action_result.add_data(data)
            hec = self._send_hec(dict(data, action=action_id, result="success", message=message,
                                      container_id=self.get_container_id()))
            if hec not in (None, 200):
                message += f" (HEC logging failed: {hec})"
            messages.append(message)
            self.save_progress(message)

        if failed and not messages:
            return action_result.set_status(phantom.APP_ERROR, "; ".join(failed))
        last = action_result.get_data()[-1] if action_result.get_data() else {}
        action_result.update_summary({"state": last.get("state"), "change_id": last.get("change_id"),
                                      "targets": len(targets)})
        return action_result.set_status(phantom.APP_SUCCESS, "; ".join(messages + failed))

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)
        if action_id == "test_connectivity":
            return self._handle_test_connectivity(param)
        if action_id == "reset_demo_state":
            return self._handle_reset(param)
        if action_id in ACTION_MAP:
            return self._handle_change(action_id, param)
        return phantom.APP_ERROR


def main():
    import argparse
    import sys

    ap = argparse.ArgumentParser()
    ap.add_argument("input_test_json", help="Input Test JSON file")
    args = ap.parse_args()
    with open(args.input_test_json) as f:
        in_json = json.dumps(json.load(f), indent=4)
    connector = KestrelDemoContainmentConnector()
    connector.print_progress_message = True
    ret_val = connector._handle_action(in_json, None)
    print(json.dumps(json.loads(ret_val), indent=4))
    sys.exit(0)


if __name__ == "__main__":
    main()
