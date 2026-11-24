#!/usr/bin/env bash
# Rebuild every installable package from source into ./dist.
#
#   ./scripts/package.sh            build
#   ./scripts/package.sh --inspect  build, then run Splunk AppInspect (cloud checks) if it is installed
#
# Outputs
#   dist/TA-esdemo-<ver>.spl                 Splunk add-on (field mappings, CIM tags, asset/identity lookups)
#   dist/DA-ESS-esdemo-<ver>.spl             ES detections (12 event-based, 1 finding-based)
#   dist/kestreldemocontainment-<ver>.tgz    SOAR app (simulated containment actions)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

echo "1/4 Lookups (Kestrel Systems assets and identities)"
python3 tools/build_lookups.py
cp TA-esdemo/lookups/esdemo_assets.csv TA-esdemo/lookups/esdemo_identities.csv generator/data/

echo "2/4 ES detections (DA-ESS-esdemo)"
python3 content/build_content.py

echo "3/4 SOAR app metadata"
python3 soar/build_app_json.py

echo "4/4 Packaging"
ver() { grep -m1 '^version' "$1" | sed 's/.*= *//'; }
TA_VER=$(ver TA-esdemo/default/app.conf)
DA_VER=$(ver content/DA-ESS-esdemo/default/app.conf)
SOAR_VER=$(python3 -c "import json;print(json.load(open('soar/kestreldemocontainment/kestreldemocontainment.json'))['app_version'])")

pack() {  # pack <parent dir> <app dir> <output>
  find "$1/$2" -name __pycache__ -prune -exec rm -rf {} +
  find "$1/$2" -type d -exec chmod 755 {} \;
  find "$1/$2" -type f -exec chmod 644 {} \;
  COPYFILE_DISABLE=1 tar --owner=0 --group=0 -C "$1" -czf "$3" "$2"
  echo "   $3"
}
rm -f dist/*.spl dist/*.tgz
pack . TA-esdemo "dist/TA-esdemo-${TA_VER}.spl"
pack content DA-ESS-esdemo "dist/DA-ESS-esdemo-${DA_VER}.spl"
pack soar kestreldemocontainment "dist/kestreldemocontainment-${SOAR_VER}.tgz"

if [[ "${1:-}" == "--inspect" ]]; then
  if command -v splunk-appinspect >/dev/null; then
    for f in dist/*.spl; do
      echo "AppInspect (cloud): $f"
      splunk-appinspect inspect "$f" --mode precert --included-tags cloud | grep -E '^\s+(error|failure|warning):'
    done
  else
    echo "splunk-appinspect not installed: pip install splunk-appinspect"
  fi
fi
echo "Done."
