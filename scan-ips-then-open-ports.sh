#!/usr/bin/env bash

# Reads Nmap .gnmap files, extracts open TCP ports, builds HTTP/HTTPS URLs,
# runs httpx to collect status codes and screenshots, optionally saves curl responses,
# supports web-only filtering, scan profiles, and generates an HTML report.
#
# Options:
#   -i, --input           Directory containing Nmap .gnmap files. Default: nmap
#   -o, --output          Output directory. Default: httpx-output
#   --curl-response       Also save curl response headers and bodies.
#   --scheme              Scheme mode: both, http, or https. Default: both
#   --timeout             Timeout in seconds. Overrides profile timeout.
#   --profile             quiet, balanced, or fast. Default: balanced
#   --web-only            Only test ports/services likely to be HTTP/HTTPS.
#   -h, --help            Show help message.
#
# Examples:
#   ./httpx-screenshot-open-ports.sh -i nmap
#   ./httpx-screenshot-open-ports.sh -i nmap --web-only
#   ./httpx-screenshot-open-ports.sh -i nmap --profile quiet
#   ./httpx-screenshot-open-ports.sh -i nmap --profile fast --curl-response
#   ./httpx-screenshot-open-ports.sh -i nmap -o web-evidence --scheme https

set -euo pipefail

INPUT_DIR="nmap"
OUTPUT_DIR="httpx-output"
SCHEME_MODE="both"
PROFILE="balanced"
TIMEOUT=""
CURL_RESPONSE=false
WEB_ONLY=false

HTTPX_RATE_LIMIT=""
HTTPX_THREADS=""
CURL_SLEEP=""

TARGETS_FILE=""
HTTPX_JSON_FILE=""
HTTPX_TEXT_FILE=""
CURL_DIR=""
REPORT_HTML=""

show_help() {
    cat << EOF
Usage:
  $0 [options]

Description:
  Extracts open TCP ports from Nmap .gnmap files, creates HTTP/HTTPS URLs,
  runs httpx against them, captures screenshots, prints status codes, and
  generates an HTML report.

Requirements:
  - ProjectDiscovery httpx
  - curl
  - Nmap .gnmap files generated with -oA or -oG

Options:
  -i, --input <dir>
      Directory containing Nmap .gnmap files.
      Default: nmap

  -o, --output <dir>
      Directory where httpx results, screenshots, curl responses, and HTML report are saved.
      Default: httpx-output

  --curl-response
      For each generated URL, run curl and save response headers and body.

  --scheme <both|http|https>
      Which URL schemes to test.
      both  = test http:// and https:// for each host:port
      http  = test only http://
      https = test only https://
      Default: both

  --profile <quiet|balanced|fast>
      Controls scan intensity.

      quiet:
        Lower concurrency and rate.
        Better for sensitive environments.

      balanced:
        Good default for normal internal assessments.

      fast:
        Higher concurrency and rate.
        Better when speed matters and alerting/noise is acceptable.

      Default: balanced

  --timeout <seconds>
      Timeout used by httpx and curl.
      Overrides the timeout chosen by the profile.

  --web-only
      Only test ports/services that are likely to be HTTP/HTTPS.
      This reduces noise by avoiding obvious non-web services such as SSH, SMB, RDP, etc.

  -h, --help
      Show this help message.

Examples:
  $0 -i nmap
  $0 -i nmap --web-only
  $0 -i nmap --profile quiet
  $0 -i nmap --profile fast --curl-response
  $0 -i nmap -o web-evidence --scheme https
  $0 -i nmap --web-only --profile quiet --curl-response
EOF
}

check_dependencies() {
    if ! command -v httpx >/dev/null 2>&1; then
        echo "[!] httpx is not installed or not in PATH."
        echo "    Install ProjectDiscovery httpx first."
        exit 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "[!] curl is not installed or not in PATH."
        exit 1
    fi
}

safe_name() {
    echo "$1" | sed 's#[/:*?<>|,=&?%# ]#_#g'
}

html_escape() {
    sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&#39;/g"
}

validate_options() {
    if [[ ! -d "$INPUT_DIR" ]]; then
        echo "[!] Input directory does not exist: $INPUT_DIR"
        exit 1
    fi

    if [[ "$SCHEME_MODE" != "both" && "$SCHEME_MODE" != "http" && "$SCHEME_MODE" != "https" ]]; then
        echo "[!] Invalid scheme mode: $SCHEME_MODE"
        echo "    Use: both, http, or https"
        exit 1
    fi

    if [[ "$PROFILE" != "quiet" && "$PROFILE" != "balanced" && "$PROFILE" != "fast" ]]; then
        echo "[!] Invalid profile: $PROFILE"
        echo "    Use: quiet, balanced, or fast"
        exit 1
    fi

    if [[ -n "$TIMEOUT" && ! "$TIMEOUT" =~ ^[0-9]+$ ]]; then
        echo "[!] Timeout must be a number."
        exit 1
    fi
}

apply_profile() {
    case "$PROFILE" in
        quiet)
            HTTPX_RATE_LIMIT="5"
            HTTPX_THREADS="5"
            CURL_SLEEP="0.50"
            [[ -z "$TIMEOUT" ]] && TIMEOUT="15"
            ;;
        balanced)
            HTTPX_RATE_LIMIT="25"
            HTTPX_THREADS="25"
            CURL_SLEEP="0.10"
            [[ -z "$TIMEOUT" ]] && TIMEOUT="10"
            ;;
        fast)
            HTTPX_RATE_LIMIT="100"
            HTTPX_THREADS="100"
            CURL_SLEEP="0"
            [[ -z "$TIMEOUT" ]] && TIMEOUT="5"
            ;;
    esac
}

is_likely_web_service() {
    local port="$1"
    local service="$2"
    local service_l
    service_l="$(echo "$service" | tr '[:upper:]' '[:lower:]')"

    case "$port" in
        80|81|88|443|591|593|8000|8008|8080|8081|8082|8088|8090|8180|8443|8834|8888|9000|9001|9080|9443|9999|10000)
            return 0
            ;;
    esac

    if [[ "$service_l" == *"http"* || "$service_l" == *"https"* || "$service_l" == *"ssl/http"* || "$service_l" == *"http-proxy"* ]]; then
        return 0
    fi

    return 1
}

extract_open_targets_from_gnmap() {
    local gnmap_file="$1"

    awk '
    /Ports:/ {
        host=$2

        split($0, parts, "Ports: ")
        split(parts[2], entries, ", ")

        for (i in entries) {
            split(entries[i], field, "/")

            port=field[1]
            state=field[2]
            proto=field[3]
            service=field[5]

            if (state == "open" && proto == "tcp") {
                if (service == "") {
                    service="unknown"
                }

                print host "|" port "|" service
            }
        }
    }
    ' "$gnmap_file"
}

build_urls() {
    local host="$1"
    local port="$2"

    case "$SCHEME_MODE" in
        both)
            echo "http://${host}:${port}"
            echo "https://${host}:${port}"
            ;;
        http)
            echo "http://${host}:${port}"
            ;;
        https)
            echo "https://${host}:${port}"
            ;;
    esac
}

save_curl_responses() {
    local url="$1"
    local name
    name="$(safe_name "$url")"

    local body_file="${CURL_DIR}/${name}.body.txt"
    local headers_file="${CURL_DIR}/${name}.headers.txt"

    echo "[+] Curling: $url"

    curl \
        --silent \
        --show-error \
        --location \
        --max-time "$TIMEOUT" \
        --insecure \
        --dump-header "$headers_file" \
        --output "$body_file" \
        "$url" || true

    if [[ "$CURL_SLEEP" != "0" ]]; then
        sleep "$CURL_SLEEP"
    fi
}

run_httpx() {
    echo "[+] Running httpx screenshots and status-code collection..."
    echo "[+] Profile: $PROFILE"
    echo "[+] httpx rate limit: $HTTPX_RATE_LIMIT"
    echo "[+] httpx threads: $HTTPX_THREADS"
    echo "[+] timeout: $TIMEOUT"

    httpx \
        -l "$TARGETS_FILE" \
        -status-code \
        -title \
        -tech-detect \
        -web-server \
        -follow-redirects \
        -timeout "$TIMEOUT" \
        -rate-limit "$HTTPX_RATE_LIMIT" \
        -threads "$HTTPX_THREADS" \
        -screenshot \
        -screenshot-output "$OUTPUT_DIR/screenshots" \
        -json \
        -o "$HTTPX_JSON_FILE" \
        | tee "$HTTPX_TEXT_FILE" || true

    echo "[+] httpx completed."
}

json_value() {
    local key="$1"
    local line="$2"

    echo "$line" | sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/p"
}

json_number() {
    local key="$1"
    local line="$2"

    echo "$line" | sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p"
}

find_screenshot_for_url() {
    local url="$1"
    local safe
    safe="$(safe_name "$url")"

    local found=""

    found="$(find "$OUTPUT_DIR/screenshots" -type f \( -name "*.png" -o -name "*.jpeg" -o -name "*.jpg" \) 2>/dev/null | grep -i "$safe" | head -n 1 || true)"

    if [[ -z "$found" ]]; then
        found="$(find "$OUTPUT_DIR/screenshots" -type f \( -name "*.png" -o -name "*.jpeg" -o -name "*.jpg" \) 2>/dev/null | head -n 1 || true)"
    fi

    echo "$found"
}

generate_html_report() {
    echo "[+] Generating HTML report..."

    cat > "$REPORT_HTML" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HTTPX Web Exposure Report</title>
<style>
body {
    font-family: Arial, sans-serif;
    margin: 24px;
    background: #f7f7f7;
    color: #222;
}
h1, h2 {
    color: #111;
}
.summary {
    background: white;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 20px;
    border: 1px solid #ddd;
}
.card {
    background: white;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 18px;
}
.meta {
    font-size: 14px;
    color: #444;
}
.status {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    background: #eee;
    font-weight: bold;
}
img {
    max-width: 100%;
    border: 1px solid #ccc;
    margin-top: 12px;
}
code {
    background: #eee;
    padding: 2px 4px;
    border-radius: 4px;
}
a {
    color: #0645ad;
}
table {
    border-collapse: collapse;
}
td, th {
    padding: 6px 10px;
    border: 1px solid #ddd;
}
</style>
</head>
<body>

<h1>HTTPX Web Exposure Report</h1>

<div class="summary">
<h2>Scan Context</h2>
<table>
<tr><th>Input directory</th><td><code>$INPUT_DIR</code></td></tr>
<tr><th>Output directory</th><td><code>$OUTPUT_DIR</code></td></tr>
<tr><th>Scheme mode</th><td><code>$SCHEME_MODE</code></td></tr>
<tr><th>Profile</th><td><code>$PROFILE</code></td></tr>
<tr><th>Timeout</th><td><code>$TIMEOUT</code></td></tr>
<tr><th>Web-only mode</th><td><code>$WEB_ONLY</code></td></tr>
<tr><th>Curl response capture</th><td><code>$CURL_RESPONSE</code></td></tr>
<tr><th>Generated targets</th><td><code>$(wc -l < "$TARGETS_FILE" | xargs)</code></td></tr>
</table>
</div>

<h2>Discovered Web Services</h2>
EOF

    if [[ ! -s "$HTTPX_JSON_FILE" ]]; then
        cat >> "$REPORT_HTML" << EOF
<div class="card">
<p>No responsive HTTP/HTTPS services were recorded by httpx.</p>
</div>
EOF
    else
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            local url status title tech webserver screenshot rel_screenshot
            url="$(json_value "url" "$line")"
            status="$(json_number "status_code" "$line")"
            title="$(json_value "title" "$line")"
            webserver="$(json_value "webserver" "$line")"
            tech="$(json_value "tech" "$line")"

            [[ -z "$url" ]] && url="unknown"
            [[ -z "$status" ]] && status="unknown"
            [[ -z "$title" ]] && title="N/A"
            [[ -z "$webserver" ]] && webserver="N/A"
            [[ -z "$tech" ]] && tech="N/A"

            screenshot="$(find_screenshot_for_url "$url")"
            rel_screenshot=""

            if [[ -n "$screenshot" ]]; then
                rel_screenshot="${screenshot#"$OUTPUT_DIR"/}"
            fi

            local url_html title_html webserver_html tech_html
            url_html="$(printf "%s" "$url" | html_escape)"
            title_html="$(printf "%s" "$title" | html_escape)"
            webserver_html="$(printf "%s" "$webserver" | html_escape)"
            tech_html="$(printf "%s" "$tech" | html_escape)"

            cat >> "$REPORT_HTML" << EOF
<div class="card">
<h3><a href="$url_html" target="_blank">$url_html</a></h3>
<p class="meta">
<span class="status">Status: $status</span><br>
<strong>Title:</strong> $title_html<br>
<strong>Web server:</strong> $webserver_html<br>
<strong>Technologies:</strong> $tech_html
</p>
EOF

            if [[ -n "$rel_screenshot" ]]; then
                cat >> "$REPORT_HTML" << EOF
<p><strong>Screenshot:</strong> <code>$rel_screenshot</code></p>
<img src="$rel_screenshot" alt="Screenshot for $url_html">
EOF
            else
                cat >> "$REPORT_HTML" << EOF
<p><strong>Screenshot:</strong> Not found or not generated.</p>
EOF
            fi

            if [[ "$CURL_RESPONSE" == true ]]; then
                local curl_name body_file headers_file
                curl_name="$(safe_name "$url")"
                body_file="curl-responses/${curl_name}.body.txt"
                headers_file="curl-responses/${curl_name}.headers.txt"

                cat >> "$REPORT_HTML" << EOF
<p>
<strong>Curl artifacts:</strong>
<a href="$headers_file" target="_blank">headers</a> |
<a href="$body_file" target="_blank">body</a>
</p>
EOF
            fi

            cat >> "$REPORT_HTML" << EOF
</div>
EOF

        done < "$HTTPX_JSON_FILE"
    fi

    cat >> "$REPORT_HTML" << EOF

</body>
</html>
EOF

    echo "[+] HTML report generated: $REPORT_HTML"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--input)
            INPUT_DIR="${2:-}"
            shift 2
            ;;

        --input=*)
            INPUT_DIR="${1#*=}"
            shift
            ;;

        -o|--output)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;

        --output=*)
            OUTPUT_DIR="${1#*=}"
            shift
            ;;

        --curl-response)
            CURL_RESPONSE=true
            shift
            ;;

        --scheme)
            SCHEME_MODE="${2:-}"
            shift 2
            ;;

        --scheme=*)
            SCHEME_MODE="${1#*=}"
            shift
            ;;

        --timeout)
            TIMEOUT="${2:-}"
            shift 2
            ;;

        --timeout=*)
            TIMEOUT="${1#*=}"
            shift
            ;;

        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;

        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;

        --web-only)
            WEB_ONLY=true
            shift
            ;;

        -h|--help)
            show_help
            exit 0
            ;;

        *)
            echo "[!] Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

check_dependencies
validate_options
apply_profile

mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/screenshots"

TARGETS_FILE="${OUTPUT_DIR}/httpx_targets.txt"
HTTPX_JSON_FILE="${OUTPUT_DIR}/httpx_results.json"
HTTPX_TEXT_FILE="${OUTPUT_DIR}/httpx_results.txt"
CURL_DIR="${OUTPUT_DIR}/curl-responses"
REPORT_HTML="${OUTPUT_DIR}/report.html"

if [[ "$CURL_RESPONSE" == true ]]; then
    mkdir -p "$CURL_DIR"
fi

: > "$TARGETS_FILE"

echo "[+] Input Nmap directory: $INPUT_DIR"
echo "[+] Output directory: $OUTPUT_DIR"
echo "[+] Scheme mode: $SCHEME_MODE"
echo "[+] Profile: $PROFILE"
echo "[+] Web-only mode: $WEB_ONLY"
echo "[+] Timeout: $TIMEOUT"
echo "[+] Curl responses: $CURL_RESPONSE"

GNMAP_COUNT=0
CANDIDATE_COUNT=0
SKIPPED_NON_WEB_COUNT=0

while IFS= read -r -d '' gnmap_file; do
    GNMAP_COUNT=$((GNMAP_COUNT + 1))
    echo "[+] Parsing: $gnmap_file"

    while IFS='|' read -r host port service; do
        [[ -z "${host:-}" || -z "${port:-}" ]] && continue

        CANDIDATE_COUNT=$((CANDIDATE_COUNT + 1))

        if [[ "$WEB_ONLY" == true ]]; then
            if ! is_likely_web_service "$port" "$service"; then
                SKIPPED_NON_WEB_COUNT=$((SKIPPED_NON_WEB_COUNT + 1))
                continue
            fi
        fi

        while read -r url; do
            [[ -z "$url" ]] && continue
            echo "$url" >> "$TARGETS_FILE"
        done < <(build_urls "$host" "$port")

    done < <(extract_open_targets_from_gnmap "$gnmap_file")

done < <(find "$INPUT_DIR" -type f -name "*.gnmap" -print0)

if [[ "$GNMAP_COUNT" -eq 0 ]]; then
    echo "[!] No .gnmap files found in: $INPUT_DIR"
    exit 1
fi

sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"

TARGET_COUNT="$(wc -l < "$TARGETS_FILE" | xargs)"

echo "[+] Parsed .gnmap files: $GNMAP_COUNT"
echo "[+] Open TCP services found: $CANDIDATE_COUNT"
echo "[+] Skipped by --web-only: $SKIPPED_NON_WEB_COUNT"
echo "[+] Generated HTTP/HTTPS targets: $TARGET_COUNT"

if [[ "$TARGET_COUNT" -eq 0 ]]; then
    echo "[!] No HTTP/HTTPS targets generated."
    echo "    If you used --web-only, try again without it."
    exit 0
fi

echo "[+] Target list:"
cat "$TARGETS_FILE"

run_httpx

if [[ "$CURL_RESPONSE" == true ]]; then
    echo "[+] Saving curl responses..."

    while read -r url; do
        [[ -z "$url" ]] && continue
        save_curl_responses "$url"
    done < "$TARGETS_FILE"

    echo "[+] Curl responses saved in: $CURL_DIR"
fi

generate_html_report

echo "[+] Done."
echo "[+] Targets file: $TARGETS_FILE"
echo "[+] httpx text results: $HTTPX_TEXT_FILE"
echo "[+] httpx JSON results: $HTTPX_JSON_FILE"
echo "[+] Screenshots directory: $OUTPUT_DIR/screenshots"
echo "[+] HTML report: $REPORT_HTML"
