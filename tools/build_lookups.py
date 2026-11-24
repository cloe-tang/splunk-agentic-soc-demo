#!/usr/bin/env python3
"""
Build the asset and identity lookups for the ES 8 demo company "Kestrel Systems".

Everything here is fictional. The email domain uses the reserved .example TLD
(RFC 2606) so no name or address can collide with a real organisation.

Output (written next to the TA so it ships inside the app):
  TA-esdemo/lookups/esdemo_assets.csv
  TA-esdemo/lookups/esdemo_identities.csv

To rebrand: change COMPANY / EMAIL_DOMAIN / NT_DOMAIN and re-run. The generator
(step 4) reads the same CSVs, so users, hosts and IPs stay consistent everywhere.
"""
import csv
import os

COMPANY = "Kestrel Systems"
EMAIL_DOMAIN = "kestrel.example"
NT_DOMAIN = "KESTREL"

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "TA-esdemo", "lookups")

SITES = {
    "SG": {"city": "Singapore", "country": "SG", "lat": "1.2830", "long": "103.8510"},
    "AU": {"city": "Sydney", "country": "AU", "lat": "-33.8680", "long": "151.2090"},
    "GB": {"city": "London", "country": "GB", "lat": "51.5150", "long": "-0.0920"},
}

# ---------------------------------------------------------------- identities
# (username, first, last, title, bunit, category, priority, site, watchlist)
# Scenario roles are noted in comments; the generator relies on these names.
PEOPLE = [
    ("mwong",    "Michelle", "Wong",      "Chief Financial Officer",     "Finance",     "executive",  "critical", "SG", "true"),
    ("agrant",   "Alan",     "Grant",     "Chief Executive Officer",     "Executive",   "executive",  "critical", "SG", "true"),
    ("lmorales", "Lucia",    "Morales",   "Chief Operating Officer",     "Executive",   "executive",  "critical", "GB", "true"),
    ("dchen",    "Daniel",   "Chen",      "Finance Manager",             "Finance",     "finance",    "high",     "SG", "false"),  # phishing victim -> lateral movement -> exfil
    ("pnair",    "Priya",    "Nair",      "Accounts Payable Lead",       "Finance",     "finance",    "high",     "SG", "false"),
    ("tokafor",  "Tobi",     "Okafor",    "Financial Analyst",           "Finance",     "finance",    "medium",   "SG", "false"),
    ("hsato",    "Hana",     "Sato",      "Payroll Specialist",          "Finance",     "finance",    "high",     "SG", "false"),
    ("bfischer", "Ben",      "Fischer",   "Treasury Analyst",            "Finance",     "finance",    "medium",   "GB", "false"),
    ("rkumar",   "Raj",      "Kumar",     "Senior Systems Administrator","IT",          "privileged", "high",     "SG", "false"),  # benign admin PowerShell
    ("egarcia",  "Elena",    "Garcia",    "Network Engineer",            "IT",          "privileged", "high",     "SG", "false"),
    ("jkim",     "Jae",      "Kim",       "Service Desk Analyst",        "IT",          "it",         "medium",   "SG", "false"),
    ("omensah",  "Owen",     "Mensah",    "Security Analyst",            "IT",          "privileged", "high",     "SG", "false"),
    ("slee",     "Sarah",    "Lee",       "Account Executive",           "Sales",       "sales",      "medium",   "AU", "false"),  # password spray success
    ("mbrown",   "Marcus",   "Brown",     "Sales Director",              "Sales",       "sales",      "high",     "AU", "false"),
    ("ajones",   "Amy",      "Jones",     "Account Executive",           "Sales",       "sales",      "low",      "AU", "false"),
    ("ksingh",   "Kiran",    "Singh",     "Sales Engineer",              "Sales",       "sales",      "low",      "GB", "false"),
    ("nwilliams","Nora",     "Williams",  "Account Manager",             "Sales",       "sales",      "low",      "GB", "false"),
    ("cwhite",   "Chris",    "White",     "Inside Sales Rep",            "Sales",       "sales",      "low",      "AU", "false"),
    ("vpatel",   "Vikram",   "Patel",     "Engineering Manager",         "Engineering", "engineering","medium",   "SG", "false"),
    ("ytan",     "Yi Ling",  "Tan",       "Software Engineer",           "Engineering", "engineering","medium",   "SG", "false"),
    ("fmuller",  "Felix",    "Muller",    "Software Engineer",           "Engineering", "engineering","low",      "GB", "false"),
    ("gsilva",   "Gabriel",  "Silva",     "DevOps Engineer",             "Engineering", "privileged", "high",     "SG", "false"),
    ("iahmed",   "Imran",    "Ahmed",     "QA Engineer",                 "Engineering", "engineering","low",      "SG", "false"),
    ("zli",      "Zhen",     "Li",        "Data Engineer",               "Engineering", "engineering","medium",   "SG", "false"),
    ("rlopez",   "Rosa",     "Lopez",     "HR Director",                 "HR",          "hr",         "high",     "SG", "false"),
    ("tnguyen",  "Thanh",    "Nguyen",    "HR Business Partner",         "HR",          "hr",         "medium",   "SG", "false"),
    ("eobrien",  "Erin",     "OBrien",    "Recruiter",                   "HR",          "hr",         "low",      "GB", "false"),
    # service accounts
    ("svc_backup",   "", "", "Backup service account",            "IT", "service_account", "high",   "SG", "false"),
    ("svc_vulnscan", "", "", "Vulnerability scanner account",     "IT", "service_account", "medium", "SG", "false"),  # benign scanner
    ("svc_sql",      "", "", "SQL Server service account",        "IT", "service_account", "high",   "SG", "false"),
]

# ---------------------------------------------------------------- assets
# (hostname, ip, category, priority, bunit, owner, site, is_expected)
SERVERS = [
    ("kes-dc01",       "10.10.0.10",  "domain_controller",      "critical", "IT",      "rkumar",       "SG", "true"),
    ("kes-dc02",       "10.10.0.11",  "domain_controller",      "critical", "IT",      "rkumar",       "SG", "true"),
    ("kes-fs01",       "10.10.0.20",  "file_server",            "high",     "IT",      "rkumar",       "SG", "true"),
    ("kes-sql01",      "10.10.0.30",  "database|finance",       "critical", "Finance", "svc_sql",      "SG", "true"),
    ("kes-erp01",      "10.10.0.31",  "erp|finance",            "critical", "Finance", "pnair",        "SG", "true"),
    ("kes-hr01",       "10.10.0.32",  "hr_system",              "high",     "HR",      "rlopez",       "SG", "true"),
    ("kes-jump01",     "10.10.0.40",  "jump_host",              "high",     "IT",      "egarcia",      "SG", "true"),
    ("kes-vulnscan01", "10.10.0.50",  "vulnerability_scanner",  "medium",   "IT",      "svc_vulnscan", "SG", "true"),
    ("kes-backup01",   "10.10.0.60",  "backup",                 "high",     "IT",      "svc_backup",   "SG", "true"),
    ("kes-web01",      "172.16.10.10","web_server|dmz",         "high",     "IT",      "gsilva",       "SG", "true"),
    ("kes-vpn01",      "172.16.10.5", "vpn_gateway|dmz",        "high",     "IT",      "egarcia",      "SG", "true"),
]

# workstation groups: (prefix, owners, subnet, site, category, bunit)
WS_GROUPS = [
    ("kes-lt-exec", ["mwong", "agrant", "lmorales"],                          "10.20.9",  None, "laptop|executive",  None),
    ("kes-ws-fin",  ["dchen", "pnair", "tokafor", "hsato", "bfischer"],        "10.20.1",  None, "workstation",       "Finance"),
    ("kes-ws-it",   ["rkumar", "egarcia", "jkim", "omensah"],                  "10.20.2",  None, "workstation|admin", "IT"),
    ("kes-ws-sales",["slee", "mbrown", "ajones", "ksingh", "nwilliams", "cwhite"], None,   None, "laptop",            "Sales"),
    ("kes-ws-eng",  ["vpatel", "ytan", "fmuller", "gsilva", "iahmed", "zli"],  "10.20.3",  None, "workstation",       "Engineering"),
    ("kes-ws-hr",   ["rlopez", "tnguyen", "eobrien"],                          "10.20.4",  None, "workstation",       "HR"),
]
SITE_SUBNET = {"SG": "10.20", "AU": "10.30", "GB": "10.40"}

ASSET_FIELDS = ["ip", "mac", "nt_host", "dns", "owner", "priority", "lat", "long",
                "city", "country", "bunit", "category", "pci_domain", "is_expected",
                "should_timesync", "should_update", "requires_av"]
IDENTITY_FIELDS = ["identity", "prefix", "nick", "first", "last", "suffix", "email",
                   "phone", "phone2", "managedBy", "priority", "bunit", "category",
                   "watchlist", "startDate", "endDate", "work_city", "work_country",
                   "work_lat", "work_long"]


def mac_for(ip):
    parts = [int(p) for p in ip.split(".")]
    return "00:50:56:%02x:%02x:%02x" % (parts[1], parts[2], parts[3])


def person_index():
    return {p[0]: p for p in PEOPLE}


def build_assets():
    people = person_index()
    rows = []
    for host, ip, cat, prio, bunit, owner, site, expected in SERVERS:
        s = SITES[site]
        rows.append({
            "ip": ip, "mac": mac_for(ip), "nt_host": host, "dns": f"{host}.{EMAIL_DOMAIN}",
            "owner": owner, "priority": prio, "lat": s["lat"], "long": s["long"],
            "city": s["city"], "country": s["country"], "bunit": bunit, "category": cat,
            "pci_domain": "trust|cardholder" if "finance" in cat else "untrust",
            "is_expected": expected, "should_timesync": "true", "should_update": "true",
            "requires_av": "true",
        })
    host_counter = {}
    for prefix, owners, subnet, _site, cat, bunit in WS_GROUPS:
        for i, owner in enumerate(owners, start=1):
            p = people[owner]
            site = p[7]
            s = SITES[site]
            if subnet and site == "SG":
                ip = f"{subnet}.{100 + i}"
            else:
                host_counter[site] = host_counter.get(site, 0) + 1
                ip = f"{SITE_SUBNET[site]}.1.{100 + host_counter[site]}"
            host = f"{prefix}-{i:03d}"
            prio = "critical" if p[6] == "critical" else ("high" if p[6] == "high" else "medium")
            rows.append({
                "ip": ip, "mac": mac_for(ip), "nt_host": host, "dns": f"{host}.{EMAIL_DOMAIN}",
                "owner": owner, "priority": prio, "lat": s["lat"], "long": s["long"],
                "city": s["city"], "country": s["country"], "bunit": bunit or p[4],
                "category": cat, "pci_domain": "untrust", "is_expected": "false",
                "should_timesync": "true", "should_update": "true", "requires_av": "true",
            })
    return rows


def build_identities(assets):
    rows = []
    for user, first, last, title, bunit, cat, prio, site, watch in PEOPLE:
        s = SITES[site]
        email = f"{first.lower().replace(' ', '')}.{last.lower()}@{EMAIL_DOMAIN}" if first else f"{user}@{EMAIL_DOMAIN}"
        # identity is pipe-delimited: every form the user appears as in logs
        forms = [user, f"{NT_DOMAIN}\\{user}", f"{user}@{EMAIL_DOMAIN}", email]
        identity = "|".join(dict.fromkeys(forms))
        manager = {"Finance": "mwong", "IT": "rkumar", "Sales": "mbrown",
                   "Engineering": "vpatel", "HR": "rlopez", "Executive": "agrant"}.get(bunit, "")
        if manager == user:
            manager = "agrant" if user != "agrant" else ""
        rows.append({
            "identity": identity, "prefix": "", "nick": first or user, "first": first,
            "last": last, "suffix": "", "email": email,
            "phone": "", "phone2": "", "managedBy": manager, "priority": prio,
            "bunit": bunit, "category": f"{cat}|{title.replace(' ', '_').lower()}",
            "watchlist": watch, "startDate": "", "endDate": "",
            "work_city": s["city"], "work_country": s["country"],
            "work_lat": s["lat"], "work_long": s["long"],
        })
    return rows


def write(path, fields, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    os.makedirs(OUT, exist_ok=True)
    assets = build_assets()
    identities = build_identities(assets)
    write(os.path.join(OUT, "esdemo_assets.csv"), ASSET_FIELDS, assets)
    write(os.path.join(OUT, "esdemo_identities.csv"), IDENTITY_FIELDS, identities)
    print(f"{COMPANY}: {len(assets)} assets, {len(identities)} identities -> {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
