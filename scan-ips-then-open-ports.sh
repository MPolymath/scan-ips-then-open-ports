#!/usr/bin/env bash

# Performs a two-step TCP Nmap scan:
# 1. Scans all TCP ports with -p- -Pn --open to find open ports even if ICMP is blocked.
# 2. Runs -sC -sV only against the open ports found for each host.
# 3. If Nmap files already exist, asks whether to reuse them or redo the scan.
# 4. Generates risk-enriched Markdown/CSV summaries.
#
# Options:
#   -t, --target   Target IP, hostname, CIDR, range, or comma-separated targets.
#   -T, --timing   Nmap timing value from 0 to 5. Example: -T4, -T 4, or --timing=4
#   -o, --output   Output directory. Default: nmap
#   -f, --force    Redo scans even if output files already exist. No prompt.
#   --reuse        Reuse existing scans if found. No prompt.
#   -h, --help     Show help message.
#
# Examples:
#   sudo ./scan-ips-then-open-ports.sh -t 192.168.1.0/24 -T4
#   sudo ./scan-ips-then-open-ports.sh -t '192.168.55.2-230' -T2 -o scans
#   sudo ./scan-ips-then-open-ports.sh -t '192.168.174.62,192.168.174.60' -T4
#   sudo ./scan-ips-then-open-ports.sh -t 10.10.10.5 -T4 --force
#   sudo ./scan-ips-then-open-ports.sh -t 10.10.10.5 -T4 --reuse

set -euo pipefail

ORIGINAL_ARGS=("$@")

TARGET=""
TIMING=""
OUTPUT_DIR="nmap"
FORCE=false
REUSE=false
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

declare -a NMAP_TARGET_ARGS

show_help() {
    cat << EOF
Usage:
  sudo $0 -t <target/range> -T <0-5|T0-T5> [-o output_dir] [--force] [--reuse]

Description:
  Runs a full TCP port scan first, then runs a targeted -sC -sV scan
  on the open TCP ports found for each discovered host.

  The script uses -Pn in both scan phases, meaning Nmap will not rely on
  ICMP/ping discovery before scanning. This is useful when ICMP is blocked.

  If existing Nmap output files are found, the script asks whether to:
    r = reuse existing files
    R = redo the scan

Options:
  -t, --target   Target IP, hostname, CIDR, range, or comma-separated targets.
                 Examples:
                   192.168.1.10
                   192.168.1.0/24
                   192.168.55.2-230
                   192.168.55.2,192.168.55.100,192.168.55.200

  -T, --timing   Nmap timing template.
                 Accepted formats:
                   -T4
                   -T 4
                   -T T4
                   --timing=4
                   --timing=T4

  -o, --output   Output directory.
                 Default:
                   nmap

  -f, --force    Redo scans even if output files already exist. No prompt.

  --reuse        Reuse existing scans if found. No prompt.

  -h, --help     Show this help message.

Examples:
  sudo $0 -t 192.168.1.0/24 -T4
  sudo $0 -t '192.168.55.2-230' -T2 -o nmap_internal
  sudo $0 -t '192.168.174.62,192.168.174.60' -T4
  sudo $0 -t 10.10.10.5 -T4 --force
  sudo $0 -t 10.10.10.5 -T4 --reuse
EOF
}

require_sudo() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "[!] Root privileges are required for this Nmap scan."
        echo "[+] Re-running with sudo..."

        exec sudo -E \
            TOOLBOX_PROFILE="${TOOLBOX_PROFILE:-}" \
            TOOLBOX_THREADS="${TOOLBOX_THREADS:-}" \
            TOOLBOX_RATE_LIMIT="${TOOLBOX_RATE_LIMIT:-}" \
            TOOLBOX_TIMEOUT="${TOOLBOX_TIMEOUT:-}" \
            TOOLBOX_SLEEP="${TOOLBOX_SLEEP:-}" \
            TOOLBOX_NMAP_TIMING="${TOOLBOX_NMAP_TIMING:-}" \
            "$0" "${ORIGINAL_ARGS[@]}"
    fi
}

check_dependencies() {
    if ! command -v nmap >/dev/null 2>&1; then
        echo "[!] nmap is not installed or not in PATH."
        exit 1
    fi
}

normalize_timing() {
    local input="$1"

    input="${input#-}"   # Converts -T4 to T4
    input="${input#T}"   # Converts T4 to 4

    if [[ ! "$input" =~ ^[0-5]$ ]]; then
        echo "[!] Invalid timing value: $1"
        echo "    Use one of: 0,1,2,3,4,5 or T0,T1,T2,T3,T4,T5 or -T4"
        exit 1
    fi

    TIMING="-T${input}"
}

safe_name() {
    echo "$1" | sed 's#[/:*?<>|, ]#_#g'
}

prepare_targets() {
    NMAP_TARGET_ARGS=()

    if [[ "$TARGET" == *","* ]]; then
        IFS=',' read -r -a raw_targets <<< "$TARGET"

        for raw_target in "${raw_targets[@]}"; do
            cleaned_target="$(echo "$raw_target" | xargs)"

            if [[ -n "$cleaned_target" ]]; then
                NMAP_TARGET_ARGS+=("$cleaned_target")
            fi
        done
    else
        NMAP_TARGET_ARGS+=("$TARGET")
    fi

    if [[ "${#NMAP_TARGET_ARGS[@]}" -eq 0 ]]; then
        echo "[!] No valid targets were provided."
        exit 1
    fi
}

ask_reuse_or_redo() {
    local scan_label="$1"
    local file_prefix="$2"
    local answer=""

    if [[ "$FORCE" == true ]]; then
        return 1
    fi

    if [[ "$REUSE" == true ]]; then
        return 0
    fi

    if [[ ! -t 0 && ! -r /dev/tty ]]; then
        echo "[!] Existing files found, but no interactive terminal is available."
        echo "    Use --force to redo scans or --reuse to reuse existing files."
        exit 1
    fi

    while true; do
        echo "" > /dev/tty
        echo "[?] Existing Nmap files found for: $scan_label" > /dev/tty
        echo "    ${file_prefix}.nmap" > /dev/tty
        echo "    ${file_prefix}.gnmap" > /dev/tty
        echo "    ${file_prefix}.xml" > /dev/tty
        echo "" > /dev/tty
        echo "    Do you want to reuse the existing Nmap files or redo the scan?" > /dev/tty
        echo "    r = reuse existing files" > /dev/tty
        echo "    R = redo scan" > /dev/tty
        printf "Choice [r/R]: " > /dev/tty

        read -r answer < /dev/tty

        case "$answer" in
            r|reuse|Reuse|REUSE)
                echo "[+] Reusing existing scan files for: $scan_label"
                return 0
                ;;
            R|redo|Redo|REDO)
                echo "[+] Redoing scan for: $scan_label"
                return 1
                ;;
            *)
                echo "[!] Invalid choice. Enter 'r' to reuse or 'R' to redo." > /dev/tty
                ;;
        esac
    done
}

parse_open_ports_from_gnmap() {
    local gnmap_file="$1"

    awk '
    /Ports:/ {
        host=$2
        ports=""

        split($0, parts, "Ports: ")
        split(parts[2], entries, ", ")

        for (i in entries) {
            split(entries[i], field, "/")

            port=field[1]
            state=field[2]
            proto=field[3]

            if (state == "open" && proto == "tcp") {
                if (ports == "") {
                    ports = port
                } else {
                    ports = ports "," port
                }
            }
        }

        if (ports != "") {
            print host " " ports
        }
    }
    ' "$gnmap_file"
}

write_summary_header() {
    local md_file="$1"
    local csv_file="$2"

    cat > "$md_file" << EOF
# Nmap TCP Scan Summary

## Scan Context

| Field | Value |
|---|---|
| Target | \`$TARGET\` |
| Parsed targets | \`${NMAP_TARGET_ARGS[*]}\` |
| Timing | \`$TIMING\` |
| Host discovery | \`-Pn\` used, ICMP/ping discovery bypassed |
| Full TCP discovery | \`-p- -Pn --open\` |
| Service detection | \`-sC -sV -Pn\` |
| Existing file behavior | Interactive prompt unless \`--force\` or \`--reuse\` is used |
| Force rerun | \`$FORCE\` |
| Auto reuse | \`$REUSE\` |
| Output directory | \`$OUTPUT_DIR\` |
| Summary timestamp | \`$TIMESTAMP\` |

## Executive Summary

This scan identified TCP services exposed by the tested target scope. A first pass scanned all TCP ports and a second pass performed service and default script detection only against confirmed open ports.

The risk level below is an automated prioritization aid. It does not replace manual validation by the tester.

## Open Services With Risk-Oriented Enrichment

| Host | Port | State | Service | Risk | Review Note | Raw Nmap Details |
|---|---:|---|---|---|---|---|
EOF

    echo "host,port,protocol,state,service,risk,review_note,raw_nmap_details" > "$csv_file"
}

write_summary_footer() {
    local md_file="$1"

    cat >> "$md_file" << EOF

## Risk Interpretation

| Risk | Meaning |
|---|---|
| High | Usually deserves priority review because it may expose administration, identity, file sharing, databases, or sensitive remote access. |
| Medium | Commonly relevant service that may require configuration, version, authentication, or exposure review. |
| Low | Usually lower priority from port exposure alone, but still needs validation in context. |
| Info | Informational or unidentified service requiring manual triage. |

## Recommended Follow-Up

- Validate whether each exposed service is expected and authorized.
- Prioritize externally exposed administrative services such as SSH, RDP, WinRM, SMB, database ports, and management interfaces.
- Review service versions for known vulnerabilities.
- Confirm whether sensitive services are restricted by firewall rules or network segmentation.
- Run targeted service-specific checks only where authorized.
- Manually validate automated risk tags before including them in a client deliverable.

## Notes

This summary is generated automatically from Nmap grepable output. It should be reviewed by the tester before being included in a client-facing report.
EOF
}

extract_services_from_gnmap() {
    local gnmap_file="$1"
    local csv_file="$2"
    local md_file="$3"

    awk -v csv="$csv_file" -v md="$md_file" '
    function csv_escape(value) {
        gsub(/"/, "\"\"", value)
        return "\"" value "\""
    }

    function md_escape(value) {
        gsub(/\|/, "\\|", value)
        return value
    }

    function risk_for(port, service) {
        service_l=tolower(service)

        if (
            port == "21"   || port == "22"   || port == "23"   ||
            port == "25"   || port == "53"   || port == "88"   ||
            port == "111"  || port == "135"  || port == "139"  ||
            port == "389"  || port == "445"  || port == "464"  ||
            port == "593"  || port == "636"  || port == "1433" ||
            port == "1521" || port == "2049" || port == "2375" ||
            port == "2376" || port == "3306" || port == "3389" ||
            port == "5432" || port == "5900" || port == "5985" ||
            port == "5986" || port == "6379" || port == "6443" ||
            port == "8080" || port == "8443" || port == "9200" ||
            port == "9300" || port == "11211" || port == "27017"
        ) {
            return "High"
        }

        if (
            port == "80"   || port == "443"  || port == "8000" ||
            port == "8081" || port == "8888" || service_l ~ /http/ ||
            service_l ~ /ssl/ || service_l ~ /https/
        ) {
            return "Medium"
        }

        if (service_l == "unknown" || service_l == "") {
            return "Info"
        }

        return "Low"
    }

    function note_for(port, service) {
        service_l=tolower(service)

        if (port == "21") return "FTP exposed; verify anonymous access, cleartext authentication, and write permissions."
        if (port == "22") return "SSH exposed; verify access control, password login, weak algorithms, and brute-force protection."
        if (port == "23") return "Telnet exposed; cleartext remote administration should be reviewed urgently."
        if (port == "25") return "SMTP exposed; check relay risk, banner leakage, TLS, and mail security configuration."
        if (port == "53") return "DNS exposed; check zone transfer, recursion, and exposure scope."
        if (port == "88" || port == "464") return "Kerberos exposed; review domain exposure and authentication hardening."
        if (port == "111" || port == "2049") return "RPC/NFS exposed; verify exported shares and access restrictions."
        if (port == "135" || port == "139" || port == "445") return "Windows file sharing/RPC exposed; prioritize SMB signing, null sessions, shares, and lateral movement risk."
        if (port == "389" || port == "636") return "LDAP exposed; check anonymous bind, TLS, directory exposure, and access control."
        if (port == "1433") return "MSSQL exposed; verify authentication, patch level, and network restrictions."
        if (port == "1521") return "Oracle listener exposed; verify listener hardening, authentication, and patch level."
        if (port == "2375" || port == "2376") return "Docker API exposed; unauthenticated Docker access can lead to host compromise."
        if (port == "3306") return "MySQL/MariaDB exposed; verify authentication, patch level, and network restrictions."
        if (port == "3389") return "RDP exposed; verify MFA, NLA, lockout policy, and exposure scope."
        if (port == "5432") return "PostgreSQL exposed; verify authentication, patch level, and network restrictions."
        if (port == "5900") return "VNC exposed; verify authentication and encryption."
        if (port == "5985" || port == "5986") return "WinRM exposed; verify administrative access control and authentication policy."
        if (port == "6379") return "Redis exposed; verify authentication, protected mode, and network restrictions."
        if (port == "6443") return "Kubernetes API exposed; verify authentication, authorization, and network exposure."
        if (port == "9200" || port == "9300") return "Elasticsearch exposed; verify authentication and data exposure risk."
        if (port == "11211") return "Memcached exposed; verify access restrictions and amplification risk."
        if (port == "27017") return "MongoDB exposed; verify authentication and data exposure risk."

        if (port == "80" || port == "443" || port == "8000" || port == "8080" || port == "8081" || port == "8443" || port == "8888" || service_l ~ /http/) {
            return "Web service exposed; review TLS, authentication, headers, directories, default pages, and application attack surface."
        }

        if (service_l == "unknown" || service_l == "") {
            return "Unknown service; manually fingerprint and validate business purpose."
        }

        return "Review service exposure, version, authentication, and business justification."
    }

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

                raw=entries[i]
                risk=risk_for(port, service)
                note=note_for(port, service)

                print host "," port "," proto "," state "," service "," risk "," csv_escape(note) "," csv_escape(raw) >> csv

                print "| " md_escape(host) " | " port "/" proto " | " state " | " md_escape(service) " | " risk " | " md_escape(note) " | `" md_escape(raw) "` |" >> md
            }
        }
    }
    ' "$gnmap_file"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)
            if [[ -z "${2:-}" ]]; then
                echo "[!] Missing value for $1"
                show_help
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;

        --target=*)
            TARGET="${1#*=}"
            shift
            ;;

        -T|--timing)
            if [[ -z "${2:-}" ]]; then
                echo "[!] Missing value for $1"
                show_help
                exit 1
            fi
            normalize_timing "$2"
            shift 2
            ;;

        -T[0-5])
            normalize_timing "$1"
            shift
            ;;

        --timing=*)
            normalize_timing "${1#*=}"
            shift
            ;;

        -o|--output)
            if [[ -z "${2:-}" ]]; then
                echo "[!] Missing value for $1"
                show_help
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;

        --output=*)
            OUTPUT_DIR="${1#*=}"
            shift
            ;;

        -f|--force)
            FORCE=true
            shift
            ;;

        --reuse)
            REUSE=true
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

require_sudo
check_dependencies

if [[ "$FORCE" == true && "$REUSE" == true ]]; then
    echo "[!] --force and --reuse cannot be used together."
    exit 1
fi

if [[ -z "$TARGET" ]]; then
    echo "[!] Missing target."
    show_help
    exit 1
fi

if [[ -z "$TIMING" ]]; then
    echo "[!] Missing timing value."
    show_help
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

prepare_targets

TARGET_SAFE="$(safe_name "$TARGET")"

DISCOVERY_PREFIX="${OUTPUT_DIR}/${TARGET_SAFE}_tcp_full"
DISCOVERY_GNMAP="${DISCOVERY_PREFIX}.gnmap"

SUMMARY_MD="${OUTPUT_DIR}/summary_${TIMESTAMP}.md"
SUMMARY_CSV="${OUTPUT_DIR}/summary_${TIMESTAMP}.csv"

write_summary_header "$SUMMARY_MD" "$SUMMARY_CSV"

echo "[+] Target: $TARGET"
echo "[+] Parsed Nmap targets: ${NMAP_TARGET_ARGS[*]}"
echo "[+] Timing: $TIMING"
echo "[+] Output directory: $OUTPUT_DIR"
echo "[+] ICMP/ping discovery bypass: enabled with -Pn"
echo "[+] Existing file behavior: ask unless --force or --reuse is used"
echo "[+] Force rerun: $FORCE"
echo "[+] Auto reuse: $REUSE"

if [[ -f "$DISCOVERY_GNMAP" ]]; then
    if ask_reuse_or_redo "full TCP discovery scan" "$DISCOVERY_PREFIX"; then
        :
    else
        echo "[+] Starting full TCP port discovery..."
        nmap -p- -Pn --open "$TIMING" -oA "$DISCOVERY_PREFIX" "${NMAP_TARGET_ARGS[@]}"
    fi
else
    echo "[+] Starting full TCP port discovery..."
    nmap -p- -Pn --open "$TIMING" -oA "$DISCOVERY_PREFIX" "${NMAP_TARGET_ARGS[@]}"
fi

if [[ ! -f "$DISCOVERY_GNMAP" ]]; then
    echo "[!] Expected grepable output not found: $DISCOVERY_GNMAP"
    exit 1
fi

echo "[+] Parsing open ports from: $DISCOVERY_GNMAP"

OPEN_HOSTS_FOUND=0

while read -r HOST PORTS; do
    [[ -z "${HOST:-}" || -z "${PORTS:-}" ]] && continue

    OPEN_HOSTS_FOUND=1

    HOST_SAFE="$(safe_name "$HOST")"
    SERVICE_PREFIX="${OUTPUT_DIR}/${HOST_SAFE}_tcp_services"
    SERVICE_GNMAP="${SERVICE_PREFIX}.gnmap"

    echo "[+] Host $HOST has open TCP ports: $PORTS"

    if [[ -f "$SERVICE_GNMAP" ]]; then
        if ask_reuse_or_redo "service scan for $HOST" "$SERVICE_PREFIX"; then
            :
        else
            echo "[+] Starting service/script scan for $HOST..."
            nmap -sC -sV -Pn "$TIMING" -p "$PORTS" -oA "$SERVICE_PREFIX" "$HOST"
        fi
    else
        echo "[+] Starting service/script scan for $HOST..."
        nmap -sC -sV -Pn "$TIMING" -p "$PORTS" -oA "$SERVICE_PREFIX" "$HOST"
    fi

    if [[ -f "$SERVICE_GNMAP" ]]; then
        extract_services_from_gnmap "$SERVICE_GNMAP" "$SUMMARY_CSV" "$SUMMARY_MD"
    else
        echo "[!] Service scan output not found for $HOST: $SERVICE_GNMAP"
    fi

done < <(parse_open_ports_from_gnmap "$DISCOVERY_GNMAP")

if [[ "$OPEN_HOSTS_FOUND" -eq 0 ]]; then
    cat >> "$SUMMARY_MD" << EOF
| No hosts with open TCP ports found | - | - | - | - | - | - |
EOF

    write_summary_footer "$SUMMARY_MD"

    echo "[+] No open TCP ports found."
    echo "[+] Summary generated:"
    echo "    $SUMMARY_MD"
    echo "    $SUMMARY_CSV"
    exit 0
fi

write_summary_footer "$SUMMARY_MD"

echo "[+] All scans completed."
echo "[+] Results saved in: $OUTPUT_DIR"
echo "[+] Client-ready summary generated:"
echo "    $SUMMARY_MD"
echo "    $SUMMARY_CSV"
