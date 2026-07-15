#!/usr/bin/env bash
# gen-report.sh <reports-dir> — build summary.json + a self-contained report.html
# from the per-scenario *.result.json + *.cast files in <reports-dir>. Host-side.
# The HTML inlines the vendored asciinema-player and embeds each recording as a
# data: URL, so report.html plays every scenario when opened locally in a browser
# — no server, no external requests.
set -euo pipefail
DIR="${1:?usage: gen-report.sh <reports-dir>}"
ASSETS="$(cd "$(dirname "${BASH_SOURCE[0]}")/report-assets" && pwd)"
cd "$DIR"

shopt -s nullglob
results=(*.result.json)
[ ${#results[@]} -gt 0 ] || { echo "no result JSONs in $DIR" >&2; exit 1; }

# --- summary.json -----------------------------------------------------------
jq -s '{
    generated_at: (now | todate),
    total: length,
    passed: [.[] | select(.result=="pass")] | length,
    failed: [.[] | select(.result=="fail")] | length,
    scenarios: .
}' "${results[@]}" > summary.json

pass=$(jq .passed summary.json); fail=$(jq .failed summary.json); total=$(jq .total summary.json)

# --- report.html ------------------------------------------------------------
{
cat <<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentjail testbed report</title>
<style>
$(cat "$ASSETS/asciinema-player.css")
body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0d1117;color:#e6edf3}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{margin:0 0 4px} .sub{color:#8b949e;margin-bottom:20px}
.tally{display:flex;gap:10px;margin-bottom:24px}
.pill{padding:6px 14px;border-radius:20px;font-weight:600}
.pill.ok{background:#12331c;color:#3fb950} .pill.bad{background:#3a1416;color:#f85149} .pill.n{background:#1c2333;color:#8b949e}
.scn{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:20px}
.scn h2{margin:0;font-size:18px;display:flex;align-items:center;gap:10px}
.badge{font-size:12px;padding:3px 10px;border-radius:12px}
.badge.pass{background:#12331c;color:#3fb950} .badge.fail{background:#3a1416;color:#f85149}
.intent{color:#8b949e;margin:4px 0 12px}
.checks{list-style:none;padding:0;margin:0 0 14px;font-size:14px}
.checks li{padding:3px 0} .c-pass::before{content:"\2713 ";color:#3fb950} .c-fail::before{content:"\2717 ";color:#f85149}
.player{border-radius:8px;overflow:hidden}
.meta{color:#6e7681;font-size:12px;margin-top:8px}
</style></head><body><div class="wrap">
<h1>agentjail testbed report</h1>
<div class="sub">clean-VM install + policy enforcement · Linux</div>
<div class="tally">
  <span class="pill ok">$pass passed</span>
  <span class="pill bad">$fail failed</span>
  <span class="pill n">$total total</span>
</div>
<script>$(cat "$ASSETS/asciinema-player.min.js")</script>
HTML

i=0
for rf in "${results[@]}"; do
    i=$((i+1))
    name=$(jq -r .scenario "$rf"); intent=$(jq -r .intent "$rf")
    result=$(jq -r .result "$rf"); dur=$(jq -r .duration_s "$rf"); ver=$(jq -r .agentjail_version "$rf")
    cast=$(jq -r .recording "$rf")
    echo "<div class=\"scn\"><h2>$name <span class=\"badge $result\">$result</span></h2>"
    echo "<div class=\"intent\">$intent</div><ul class=\"checks\">"
    jq -r '.checks[] | (if .pass then "c-pass" else "c-fail" end) + "\t" + .label' "$rf" \
        | while IFS=$'\t' read -r cls label; do echo "<li class=\"$cls\">$label</li>"; done
    echo "</ul>"
    if [ -f "$cast" ]; then
        b64=$(base64 -w0 "$cast")
        echo "<div class=\"player\" id=\"p$i\"></div>"
        echo "<script>AsciinemaPlayer.create('data:text/plain;base64,$b64',document.getElementById('p$i'),{fit:'width',terminalFontSize:'13px',idleTimeLimit:2});</script>"
    fi
    echo "<div class=\"meta\">agentjail $ver · ${dur}s · recording: $cast</div></div>"
done

echo "</div></body></html>"
} > report.html

echo "report: $DIR/report.html  ($pass/$total passed)"
