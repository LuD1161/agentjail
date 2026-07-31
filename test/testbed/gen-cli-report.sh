#!/usr/bin/env bash
# gen-cli-report.sh <casts-dir> [out-dir] — build a self-contained CLI regression
# report (index.html) from a directory of per-scenario asciinema *.cast files.
#
# This is the Linux twin of the mac-cli-report/: it mirrors that report's layout
# (at-a-glance tiles, a jump-to summary table, a findings section, and one inline
# asciinema player per scenario) but derives every count LIVE from the recorded
# casts instead of being hand-authored. For each scenario it reconstructs the
# terminal byte stream from the cast's "o" events, strips ANSI, and counts the
# PASS / FAIL / SKIP / FINDING lines the scenarios print (ok()/bad()/skip()/
# finding() and reportlib's scn_check). The player CSS/JS are inlined from
# report-assets/ and each cast is embedded as base64 — no external requests.
#
#   gen-cli-report.sh reports/<ts>            -> reports/<ts>/index.html
#   gen-cli-report.sh reports/<ts> linux-cli-report
#
# Scenarios recorded in `single` mode (the whole script wrapped in asciinema rec)
# are the input; the tmux two-terminal flow (mcp-remediation-loop) is not part of
# this suite.
set -euo pipefail

CASTS_DIR="${1:?usage: gen-cli-report.sh <casts-dir> [out-dir]}"
OUT_DIR="${2:-$CASTS_DIR}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSETS="$HERE/report-assets"
mkdir -p "$OUT_DIR/casts"

command -v jq >/dev/null 2>&1 || { echo "gen-cli-report: jq is required" >&2; exit 1; }

# Ordered scenarios + metadata, mirroring mac-cli-report. Fields are TAB-separated:
#   name <TAB> covers <TAB> blurb <TAB> check|check|check
meta() {
cat <<'META'
cli-tour	Whole CLI surface, end-to-end	Every command exercised in one pass with real behaviour + assertions, finishing with the uninstall teardown.	status/doctor health|try + run enforcement|mcp/policy/trust/telemetry/ui|uninstall --help is safe
e2e-smoke	Two-tier enforcement	The original smoke test: hook tier (PreToolUse allow/deny) and shield tier (kernel sandbox) on the installed binaries.	hook wired + daemon active|deny ~/.ssh, ~/.aws, rm -rf /|shield blocks key read/write|decisions persisted
try-policy	Dry-run decision matrix	try --json across file + command rules — nothing is executed, the decision is asserted.	deny ssh/aws/agentjail-self|allow project + /tmp|deny sudo, rm -rf, chmod 777, force-push
run-shield	Shielded execution	run -- executes inside the OS sandbox; credential reads/writes are blocked, the project cwd is writable.	allowed command runs|private-key read blocked|~/.ssh write blocked|project write allowed
policy-mgmt	Rule management	policy list/add/remove plus the guard that refuses disabling a core rule without --force + a TTY.	valid Rego rule installs|remove cleans up|core-rule disable refused (non-TTY)
mcp	MCP inspection + guard	list/scan/where/tools discovery, and the guard that refuses self-approval of MCP servers without a human TTY.	list + scan discovery|where / tools|allow/block REFUSED in non-TTY
skill	Skill policy + guard	Skill listing and the non-TTY guard refusing an agent from self-approving a skill.	skill list|ask/clear REFUSED in non-TTY
secret	Credential vault surface	Exercises the scoped-credential vault and detects whether the agentjail-secrets binary is shipped (a packaging finding if absent).	secret list (empty)|vault binary presence checked|absence reported as FINDING, not a fail
trust	Project overlay trust	trust / trust list / untrust round-trip on a well-formed project policy overlay, with sha256 match state.	trust a clean overlay|list shows sha + [ok]|untrust removes it
egress-grants	Runtime host grants	The runtime egress-widening flow: pending grants list and an allow-host request awaiting human approval.	grants (empty)|allow host creates pending grant|grants lists it
observability	sessions / logs / replay	The decision store surface: session listing, the live logs stream, and replay.	sessions usage + list|logs stream (capped)|replay best-effort
telemetry	Telemetry toggle	Local telemetry view/disable/enable round-trip; leaves the guest enabled.	view queued events|disable / enable|state restored
ui	Local web UI	Headless probe of the local web UI — starts the server, curls it, asserts HTTP 200, tears it down.	serves 127.0.0.1:9101|HTTP 200 + title|process cleaned up
help-regression	The --help fix	Regression guard: every DisableFlagParsing command's --help now prints usage and never acts.	--help prints usage|uninstall --help leaves ~/.agentjail intact|install --help does not install|-- passthrough preserved
lifecycle	Health + idempotency	version / status / doctor and install idempotency (repeated status is stable).	version + banner|status + doctor green|install re-run idempotent
META
}

# --- per-cast text extraction + counting ------------------------------------
# Reconstruct the terminal stream from the cast's "o" events (raw, no separators),
# strip ANSI/OSC/CR, and count assertion lines the scenarios emit.
cast_text() {
    tail -n +2 "$1" | jq -j 'select(.[1]=="o") | .[2]' 2>/dev/null \
        | sed -E $'s/\x1b\\[[0-9;?]*[A-Za-z]//g; s/\x1b\\][^\x07]*(\x07|\x1b\\\\)//g; s/\x1b[()][AB0]//g; s/\r//g'
}
count_tok() { grep -cE "^[[:space:]]*$1[[:space:]]" <<<"$2" || true; }

# --- accumulate -------------------------------------------------------------
declare -a NAMES=() COVERS=() BLURBS=() CHECKS=()
declare -a PASS=() FAIL=() SKIP=() HASCAST=() FINDTEXT=()
TOTP=0; TOTF=0; TOTS=0; SUITES=0; NFIND=0

while IFS=$'\t' read -r name cover blurb checks; do
    [ -n "$name" ] || continue
    NAMES+=("$name"); COVERS+=("$cover"); BLURBS+=("$blurb"); CHECKS+=("$checks")
    local_cast="$CASTS_DIR/${name}.cast"
    if [ -f "$local_cast" ]; then
        cp "$local_cast" "$OUT_DIR/casts/${name}.cast"
        txt="$(cast_text "$local_cast")"
        p=$(count_tok PASS "$txt"); f=$(count_tok FAIL "$txt"); s=$(count_tok SKIP "$txt")
        find_lines="$(grep -E "^[[:space:]]*FINDING[[:space:]]" <<<"$txt" | sed -E 's/^[[:space:]]*FINDING[[:space:]]+//' || true)"
        PASS+=("$p"); FAIL+=("$f"); SKIP+=("$s"); HASCAST+=(1); FINDTEXT+=("$find_lines")
        TOTP=$((TOTP+p)); TOTF=$((TOTF+f)); TOTS=$((TOTS+s)); SUITES=$((SUITES+1))
        [ -n "$find_lines" ] && NFIND=$((NFIND+1))
    else
        PASS+=(0); FAIL+=(0); SKIP+=(0); HASCAST+=(0); FINDTEXT+=("")
        echo "gen-cli-report: WARN no cast for '$name'" >&2
    fi
done < <(meta)

GEN_DATE="$(date -u +%Y-%m-%d)"
VER="$(cat "$CASTS_DIR/version.txt" 2>/dev/null || echo unknown)"
STATE="green"; [ "$TOTF" -gt 0 ] && STATE="red"

# --- emit HTML --------------------------------------------------------------
esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
HTML="$OUT_DIR/index.html"
{
cat <<HEAD
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentjail CLI Regression Report — Linux</title>
<style>
HEAD
cat "$ASSETS/asciinema-player.css"
cat <<'CSS'
</style>
<style>
  :root{
    --bg:#f6f7f9; --surface:#fff; --surface-2:#eef1f4; --border:#dce1e8;
    --ink:#131a22; --muted:#586576; --accent:#0d9488; --accent-ink:#0a6b62; --accent-soft:#d7f2ee;
    --pass:#15803d; --pass-soft:#dcfce7; --fail:#c81e1e; --fail-soft:#fbe1e1;
    --warn:#b45309; --warn-soft:#fbeacc;
    --shadow:0 1px 2px rgba(19,26,34,.06),0 8px 24px rgba(19,26,34,.05);
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  @media (prefers-color-scheme:dark){:root{
    --bg:#0d1218; --surface:#151d27; --surface-2:#1c2732; --border:#28343f;
    --ink:#e7eef4; --muted:#8b99a9; --accent:#2dd4bf; --accent-ink:#5fe6d6; --accent-soft:#0f302d;
    --pass:#4ade80; --pass-soft:#122a1c; --fail:#f77; --fail-soft:#2d1618;
    --warn:#fbbf24; --warn-soft:#2c2410; --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);}}
  :root[data-theme="light"]{
    --bg:#f6f7f9; --surface:#fff; --surface-2:#eef1f4; --border:#dce1e8;
    --ink:#131a22; --muted:#586576; --accent:#0d9488; --accent-ink:#0a6b62; --accent-soft:#d7f2ee;
    --pass:#15803d; --pass-soft:#dcfce7; --fail:#c81e1e; --fail-soft:#fbe1e1;
    --warn:#b45309; --warn-soft:#fbeacc; --shadow:0 1px 2px rgba(19,26,34,.06),0 8px 24px rgba(19,26,34,.05);}
  :root[data-theme="dark"]{
    --bg:#0d1218; --surface:#151d27; --surface-2:#1c2732; --border:#28343f;
    --ink:#e7eef4; --muted:#8b99a9; --accent:#2dd4bf; --accent-ink:#5fe6d6; --accent-soft:#0f302d;
    --pass:#4ade80; --pass-soft:#122a1c; --fail:#f77; --fail-soft:#2d1618;
    --warn:#fbbf24; --warn-soft:#2c2410; --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);}
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  @media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55;
    font-size:16px;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1000px;margin:0 auto;padding:clamp(24px,5vw,60px) clamp(18px,4vw,40px)}
  a{color:var(--accent-ink);text-decoration:none}
  a:hover{text-decoration:underline}
  :focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
  .eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;
    color:var(--accent-ink);display:flex;gap:10px;align-items:center}
  .eyebrow .dot{width:7px;height:7px;border-radius:50%;background:var(--accent)}
  h1{font-size:clamp(28px,5vw,42px);line-height:1.08;margin:.35em 0 .2em;letter-spacing:-.02em;text-wrap:balance}
  .lede{color:var(--muted);max-width:64ch;font-size:clamp(15px,2vw,17px)}
  .meta{font-family:var(--mono);font-size:12.5px;color:var(--muted);margin-top:16px;display:flex;gap:8px 20px;flex-wrap:wrap}
  .meta b{color:var(--ink);font-weight:600}
  section{margin-top:clamp(38px,6vw,56px)}
  h2{font-size:13px;font-family:var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);
    margin:0 0 18px;padding-bottom:10px;border-bottom:1px solid var(--border)}
  h2 .n{color:var(--accent-ink);margin-right:10px}
  code{font-family:var(--mono);font-size:.9em;background:var(--surface-2);padding:.12em .4em;border-radius:5px;border:1px solid var(--border)}
  .tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
  @media(max-width:680px){.tiles{grid-template-columns:repeat(2,1fr)}}
  .tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px;box-shadow:var(--shadow)}
  .tile .k{font-size:clamp(30px,5vw,40px);font-weight:680;letter-spacing:-.03em;font-variant-numeric:tabular-nums;line-height:1}
  .tile .l{font-family:var(--mono);font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:8px}
  .tile.good .k{color:var(--pass)} .tile.bad .k{color:var(--fail)} .tile.acc .k{color:var(--accent-ink)}
  .cards{display:flex;flex-direction:column;gap:16px}
  .defect{background:var(--surface);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);
    overflow:hidden;display:grid;grid-template-columns:6px 1fr}
  .defect .stripe{background:var(--warn)}
  .defect .body{padding:20px 22px}
  .defect .top{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap;margin-bottom:8px}
  .defect .id{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .defect h3{margin:0;font-size:18px;letter-spacing:-.01em;flex:1;min-width:220px}
  .sev{font-family:var(--mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;padding:3px 9px;border-radius:999px;font-weight:600;white-space:nowrap;background:var(--warn-soft);color:var(--warn)}
  .defect p{margin:.5em 0;color:var(--ink)}
  .tbl-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}
  table.tbl{width:100%;border-collapse:collapse;font-size:14px}
  .tbl th,.tbl td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--border);white-space:nowrap}
  .tbl thead th{font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);background:var(--surface-2);font-weight:600}
  .tbl tbody tr{cursor:pointer}
  .tbl tbody tr:last-child td{border-bottom:none}
  .tbl tbody tr:hover{background:var(--surface-2)}
  .tbl .name a{font-family:var(--mono);font-size:13px;font-weight:600}
  .tbl td.num{text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono)}
  .p{color:var(--pass);font-weight:600} .f{color:var(--fail);font-weight:600} .s{color:var(--muted)}
  .chip{font-family:var(--mono);font-size:11px;padding:2px 8px;border-radius:999px;font-weight:600}
  .chip.ok{background:var(--pass-soft);color:var(--pass)} .chip.bad{background:var(--fail-soft);color:var(--fail)} .chip.find{background:var(--warn-soft);color:var(--warn)}
  .scen{scroll-margin-top:16px;background:var(--surface);border:1px solid var(--border);border-radius:14px;
    box-shadow:var(--shadow);padding:22px 24px;margin-top:18px}
  .scen-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px}
  .scen-head h3{margin:0;font-family:var(--mono);font-size:18px;letter-spacing:-.01em;color:var(--accent-ink)}
  .scen-head .top{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .blurb{color:var(--muted);margin:.5em 0 .3em;max-width:70ch}
  .scen-res{font-family:var(--mono);font-size:13px;margin:.2em 0 .8em}
  .checks{margin:0 0 16px;padding:0;list-style:none;display:flex;flex-wrap:wrap;gap:7px 10px}
  .checks li{font-family:var(--mono);font-size:11.5px;color:var(--muted);background:var(--surface-2);
    border:1px solid var(--border);border-radius:999px;padding:3px 10px}
  .player{border-radius:10px;overflow:hidden;border:1px solid var(--border);background:#121820}
  .player .asciinema-player{font-size:13px}
  .noplayer{font-family:var(--mono);font-size:12px;color:var(--muted);padding:14px;background:var(--surface-2);border-radius:10px}
  .note{background:var(--accent-soft);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);
    border-radius:12px;padding:16px 18px;font-size:14px}
  .note b{color:var(--accent-ink)}
  footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--border);font-family:var(--mono);
    font-size:12px;color:var(--muted);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
</style>
</head>
<body>
<div class="wrap" id="top">
  <header>
    <div class="eyebrow"><span class="dot"></span>agentjail · Linux Lima testbed · release gate</div>
    <h1>CLI Regression Report</h1>
    <p class="lede">Every <code>agentjail</code> command exercised on a clean-VM install through the real
      user path. Each scenario below carries its own terminal recording — press play. This is the Linux
      twin of the macOS Tart run.</p>
CSS
cat <<HEAD
    <div class="meta">
      <span>build&nbsp;<b>$(printf '%s' "$VER" | esc)</b></span><span>target&nbsp;<b>linux/amd64</b></span>
      <span>host&nbsp;<b>Lima QEMU VM · userns · systemd</b></span><span>date&nbsp;<b>$GEN_DATE</b></span>
    </div>
  </header>

  <section>
    <h2><span class="n">01</span>At a glance</h2>
    <div class="tiles">
      <div class="tile good"><div class="k">$TOTP</div><div class="l">checks passing</div></div>
      <div class="tile bad"><div class="k">$TOTF</div><div class="l">failing</div></div>
      <div class="tile acc"><div class="k">$SUITES</div><div class="l">recorded suites</div></div>
      <div class="tile"><div class="k">$NFIND</div><div class="l">findings</div></div>
    </div>
  </section>

  <section>
    <h2><span class="n">02</span>Scenarios — jump to any recording</h2>
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr><th>Scenario</th><th>Covers</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Skip</th><th>State</th></tr></thead>
        <tbody>
HEAD
for i in "${!NAMES[@]}"; do
    n="${NAMES[$i]}"; [ "${HASCAST[$i]}" = 1 ] || continue
    cov="$(printf '%s' "${COVERS[$i]}" | esc)"
    chip='<span class="chip ok">green</span>'
    [ "${FAIL[$i]}" -gt 0 ] && chip='<span class="chip bad">red</span>'
    [ -n "${FINDTEXT[$i]}" ] && chip="$chip <span class=\"chip find\">finding</span>"
    printf '<tr onclick="location.hash=%s"><td class="name"><a href="#sc-%s">%s</a></td><td>%s</td><td class="num"><span class="p">%s</span></td><td class="num"><span class="%s">%s</span></td><td class="num"><span class="s">%s</span></td><td>%s</td></tr>\n' \
        "'sc-$n'" "$n" "$n" "$cov" "${PASS[$i]}" "$([ "${FAIL[$i]}" -gt 0 ] && echo f || echo s)" "${FAIL[$i]}" "${SKIP[$i]}" "$chip"
done
cat <<'MID'
        </tbody>
      </table>
    </div>
  </section>
MID

# Findings section (only if any)
if [ "$NFIND" -gt 0 ]; then
    echo '  <section>'
    echo '    <h2><span class="n">03</span>Findings</h2>'
    echo '    <div class="cards">'
    fnum=0
    for i in "${!NAMES[@]}"; do
        [ -n "${FINDTEXT[$i]}" ] || continue
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            fnum=$((fnum+1))
            echo "      <div class=\"defect\"><div class=\"stripe\"></div><div class=\"body\">"
            echo "        <div class=\"top\"><span class=\"id\">FINDING-$fnum</span><h3>$(printf '%s' "${NAMES[$i]}" | esc)</h3><span class=\"sev\">packaging</span></div>"
            echo "        <p>$(printf '%s' "$line" | esc) — surfaced by the <a href=\"#sc-${NAMES[$i]}\">${NAMES[$i]}</a> suite (reported, not silently skipped).</p>"
            echo "      </div></div>"
        done <<< "${FINDTEXT[$i]}"
    done
    echo '    </div>'
    echo '  </section>'
fi

# Per-scenario recordings
cat <<'REC'
  <section>
    <h2><span class="n">04</span>Per-scenario recordings</h2>
REC
for i in "${!NAMES[@]}"; do
    n="${NAMES[$i]}"; [ "${HASCAST[$i]}" = 1 ] || continue
    blurb="$(printf '%s' "${BLURBS[$i]}" | esc)"
    b64="$(base64 -w0 "$OUT_DIR/casts/${n}.cast" 2>/dev/null || base64 "$OUT_DIR/casts/${n}.cast" | tr -d '\n')"
    printf '    <section id="sc-%s" class="scen">\n' "$n"
    printf '      <div class="scen-head"><h3>%s</h3><a class="top" href="#top">↑ top</a></div>\n' "$n"
    printf '      <p class="blurb">%s</p>\n' "$blurb"
    printf '      <div class="scen-res"><span class="p">%s pass</span> · <span class="%s">%s fail</span> · <span class="s">%s skip</span></div>\n' \
        "${PASS[$i]}" "$([ "${FAIL[$i]}" -gt 0 ] && echo f || echo s)" "${FAIL[$i]}" "${SKIP[$i]}"
    printf '      <ul class="checks">'
    IFS='|' read -ra cks <<< "${CHECKS[$i]}"
    for c in "${cks[@]}"; do printf '<li>%s</li>' "$(printf '%s' "$c" | esc)"; done
    printf '</ul>\n'
    printf '      <div class="player" id="p-%s" data-cast="data:text/plain;base64,%s"></div>\n' "$n" "$b64"
    printf '    </section>\n'
done
cat <<REC
  </section>

  <section>
    <h2><span class="n">05</span>How it ran</h2>
    <div class="note">The suite runs inside a persistent <b>Lima</b> QEMU VM that behaves like a real
      end-user machine — a full Ubuntu kernel, <b>systemd</b>, user namespaces for the shield, no Go
      toolchain, no host mounts. agentjail is installed the way a human would: a release tarball fed to
      the shipped <b>install.sh</b> once, with daemon and hook readiness verified immediately. This is the
      Linux half of the release gate (<code>make e2e-release</code>).</div>
  </section>

  <footer>
    <span>agentjail CLI regression · Linux Lima testbed</span>
    <span>$TOTP pass · $TOTF fail · $TOTS skip · $NFIND findings</span>
  </footer>
</div>
<script>
REC
cat "$ASSETS/asciinema-player.min.js"
cat <<'JS'
</script>
<script>
  function decodeCast(uri){
    var b64=uri.slice(uri.indexOf(",")+1);
    var bin=atob(b64), bytes=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++){ bytes[i]=bin.charCodeAt(i); }
    return new TextDecoder("utf-8").decode(bytes);
  }
  function initPlayers(){
    if(typeof AsciinemaPlayer==="undefined") return;
    document.querySelectorAll(".player[data-cast]").forEach(function(el){
      var uri=el.getAttribute("data-cast");
      el.removeAttribute("data-cast");
      try{
        AsciinemaPlayer.create({data: decodeCast(uri)}, el,
          {autoPlay:false, preload:true, controls:true, fit:"width", idleTimeLimit:2});
      }catch(e){ el.innerHTML='<div class="noplayer">player error: '+e+'</div>'; }
    });
  }
  if(document.readyState!=="loading") initPlayers(); else document.addEventListener("DOMContentLoaded", initPlayers);
</script>
</body>
</html>
JS
} > "$HTML"

echo "gen-cli-report: wrote $HTML"
echo "  $SUITES suites · $TOTP pass · $TOTF fail · $TOTS skip · $NFIND findings"
