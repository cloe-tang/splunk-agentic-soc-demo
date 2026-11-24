TA-esdemo 1.0.0 - ES 8 demo add-on for simulated "Kestrel Systems" data

What it does
  Search-time JSON extraction, CIM field EVALs, eventtypes and tags for the
  demo sourcetypes in index=esdemo, plus asset and identity lookups.

Sourcetype            -> CIM data model
  esdemo:auth             Authentication
  esdemo:endpoint:process Endpoint.Processes
  esdemo:email            Email
  esdemo:proxy            Web (Proxy)
  esdemo:firewall         Network_Traffic
  esdemo:change           Change.Account_Management
  esdemo:o365:audit       (intentionally unmapped - Detection Builder gap)

Install
  Splunk Cloud: Apps > Manage Apps > Install app from file (TA-esdemo-1.0.0.spl).
  Install on the search head only. No inputs, no index-time parsing required.

All company names, users, hosts and domains are fictional (kestrel.example).
