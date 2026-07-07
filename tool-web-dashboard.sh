#!/bin/bash

# Bird Tool Web Analyzer - Dashboard Generator v3 (sem LLM)
# Página unificada de subdomínios com status, IPs, portas/serviços, e busca em repos
# Uso: ./tool-web-dashboard.sh
# Usa Shodan InternetDB (gratuito) + Shodan API (pago, fallback)
# Análise baseada em regras — não requer Ollama/LLM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/OUT-WEB-BIRD"
DASHBOARD_DIR="${SCRIPT_DIR}/dashboard"
ASSETS_DIR="${DASHBOARD_DIR}/assets"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
SCOPE_FILE="${OUT_DIR}/.current-scope"
PRIMARY_DOMAIN=""
REPORT_TITLE="W-BRID"
AI_ENABLED="${BIRD_AI_ENABLED:-0}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Try to get Shodan API Key from file if not in environment
if [[ -z "$SHODAN_API_KEY" && -f "$HOME/.shodan-api" ]]; then
    SHODAN_API_KEY=$(cat "$HOME/.shodan-api" | head -n 1 | tr -d '[:space:]')
    [[ -n "$SHODAN_API_KEY" ]] && log_info "Utilizando Shodan API key extraída de ~/.shodan-api"
fi

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# ============================================
# SCOPE DETECTION
# ============================================
SCOPE_DOMAINS_FILE="${TEMP_DIR}/scope_domains.txt"
TWO_LEVEL_TLDS="com.br org.br net.br edu.br gov.br mil.br co.uk org.uk net.uk co.nz org.nz net.nz com.au org.au net.au"

extract_base_domain() {
    local target="$1"
    local tld2=$(echo "$target" | awk -F'.' '{print $(NF-1)"."$NF}')
    if echo "$TWO_LEVEL_TLDS" | grep -qw "$tld2"; then
        echo "$target" | awk -F'.' '{if(NF>=3) print $(NF-2)"."$(NF-1)"."$NF; else print $0}'
    else
        echo "$target" | awk -F'.' '{if(NF>=2) print $(NF-1)"."$NF; else print $0}'
    fi
}

build_scope() {
    > "$SCOPE_DOMAINS_FILE"
    if [[ -s "$SCOPE_FILE" ]]; then
        local saved_scope
        saved_scope=$(head -n 1 "$SCOPE_FILE" | sed -E 's#^https?://##;s#/.*$##;s/:.*$//' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        [[ -n "$saved_scope" ]] && echo "$saved_scope" > "$SCOPE_DOMAINS_FILE"
    fi
    if [[ ! -s "$SCOPE_DOMAINS_FILE" ]]; then
    for target_dir in "$OUT_DIR"/*/; do
        [[ ! -d "$target_dir" ]] && continue
        local target=$(basename "$target_dir")
        [[ "$target" == "Host" || "$target" == "host" || ! "$target" =~ \. ]] && continue
        extract_base_domain "$target" >> "$SCOPE_DOMAINS_FILE"
    done
    fi
    sort -u "$SCOPE_DOMAINS_FILE" -o "$SCOPE_DOMAINS_FILE"
    PRIMARY_DOMAIN=$(head -n 1 "$SCOPE_DOMAINS_FILE")
    [[ $(wc -l < "$SCOPE_DOMAINS_FILE" | tr -d ' ') -gt 1 ]] && PRIMARY_DOMAIN="MULTI-SCOPE"
    REPORT_TITLE="W-BRID - ${PRIMARY_DOMAIN:-ESCOPO}"
    export OUT_DIR DASHBOARD_DIR PRIMARY_DOMAIN REPORT_TITLE
    log_info "Escopo: $(cat "$SCOPE_DOMAINS_FILE" | tr '\n' ', ' | sed 's/,$//')"
}

is_in_scope() {
    local candidate="${1,,}"
    candidate="${candidate#*://}"
    candidate="${candidate%%/*}"
    candidate="${candidate%%:*}"
    candidate="${candidate%.}"
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        [[ "$candidate" == "$domain" || "$candidate" == *."$domain" ]] && return 0
    done < "$SCOPE_DOMAINS_FILE"
    return 1
}

strip_ansi() {
    python3 -c "
import re,sys
d=open(sys.argv[1]).read()
d=re.sub(chr(27)+r'\[[0-9;]*[mKHJABCDs]?','',d)
d=re.sub(r'\[?[0-9;]*[mKHJ]','',d)
d=re.sub(r'^0m','',d,flags=re.MULTILINE)
print(d,end='')
" "$1" 2>/dev/null || cat "$1"
}

# ============================================
# DATA PROCESSING
# ============================================

# Files for correlating data
SUBS_FILE="${TEMP_DIR}/all_subs.txt"
IP_MAP_FILE="${TEMP_DIR}/ip_map.txt"       # format: subdomain|ip
URLS_FILE="${TEMP_DIR}/urls_clean.txt"
CRAFTJS_FILE="${TEMP_DIR}/craftjs_parsed.json"
FINAL_FINDINGS_FILE="${TEMP_DIR}/final_findings.jsonl"
SHODAN_CACHE="${TEMP_DIR}/shodan_cache"

process_all_data() {
    log_info "Processando TODO o conteúdo de OUT-WEB-BIRD..."

    local subs_raw="${TEMP_DIR}/subs_raw.txt"
    local urls_raw="${TEMP_DIR}/urls_raw.txt"
    > "$subs_raw" && > "$urls_raw"
    > "$IP_MAP_FILE" && > "$CRAFTJS_FILE" && > "$FINAL_FINDINGS_FILE"
    > "${TEMP_DIR}/targets.txt"
    mkdir -p "$SHODAN_CACHE"

    local total_files=0

    for target_dir in "$OUT_DIR"/*/; do
        [[ ! -d "$target_dir" ]] && continue
        local target=$(basename "$target_dir")
        is_in_scope "$target" || continue
        echo "$target" >> "${TEMP_DIR}/targets.txt"

        for file in "$target_dir"/*; do
            [[ ! -f "$file" || ! -s "$file" ]] && continue
            local fname=$(basename "$file")
            total_files=$((total_files + 1))

            case "$fname" in
                *-assetfinder|*-subfinder|*-sublist3r)
                    cat "$file" >> "$subs_raw" ;;

                *-fierce)
                    # Extract Found: entries → domain→IP mapping
                    grep "^Found:" "$file" 2>/dev/null | while IFS= read -r line; do
                        if [[ "$line" =~ Found:\ ([a-zA-Z0-9._-]+)\.\ \(([0-9.]+)\) ]]; then
                            local fdomain="${BASH_REMATCH[1]}"
                            local fip="${BASH_REMATCH[2]}"
                            echo "$fdomain" >> "$subs_raw"
                            echo "${fdomain}|${fip}" >> "$IP_MAP_FILE"
                        fi
                    done ;;

                *-dnsenum|*-dnsrecon)
                    # Strip ANSI before parsing
                    local clean=$(strip_ansi "$file")
                    local bd=$(extract_base_domain "$target")
                    # Extract subdomains
                    echo "$clean" | grep -oE "[a-zA-Z0-9][-a-zA-Z0-9]*\.$bd" 2>/dev/null >> "$subs_raw"
                    # Extract A record mappings (subdomain → IP)
                    echo "$clean" | grep -E "IN\s+A\s+" 2>/dev/null | while IFS= read -r line; do
                        local sub=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
                        local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
                        if [[ -n "$sub" && -n "$ip" ]] && is_in_scope "$sub"; then
                            echo "${sub}|${ip}" >> "$IP_MAP_FILE"
                        fi
                    done
                    # Extract CNAME mappings
                    echo "$clean" | grep -E "IN\s+CNAME" 2>/dev/null | while IFS= read -r line; do
                        local sub=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
                        if [[ -n "$sub" ]] && is_in_scope "$sub"; then
                            echo "$sub" >> "$subs_raw"
                        fi
                    done ;;

                *-hakrawler|*-s-hakrawler|*-URL-*|*-FULL-URLs)
                    grep -E '^https?://' "$file" 2>/dev/null >> "$urls_raw" ;;

                *-bird-craftjs|*-bird-crafjs)
                    # Parse CRAFTJS findings
                    local titulo="" dado="" url=""
                    while IFS= read -r line; do
                        if [[ "$line" =~ ^TITULO:\ (.+)$ ]]; then titulo="${BASH_REMATCH[1]}"
                        elif [[ "$line" =~ ^DADO:\ (.+)$ ]]; then dado="${BASH_REMATCH[1]}"
                        elif [[ "$line" =~ ^URL:\ (.+)$ ]]; then
                            url="${BASH_REMATCH[1]}"
                            if [[ -n "$titulo" && -n "$dado" ]]; then
                                echo "{\"titulo\":\"$(echo "$titulo" | sed 's/"/\\"/g')\",\"dado\":\"$(echo "$dado" | sed 's/"/\\"/g')\",\"url\":\"$(echo "$url" | sed 's/"/\\"/g')\"}" >> "$CRAFTJS_FILE"
                                titulo="" dado="" url=""
                            fi
                        fi
                    done < "$file" 2>/dev/null ;;

                *-bird-craftjs.json)
                    jq -c '.endpoints[]? | {titulo:("Endpoint " + (.method // "GET") + " [" + (.confidence // "n/a") + "]"),dado:(.url // ""),url:(.sources[0] // "")}' "$file" 2>/dev/null >> "$CRAFTJS_FILE"
                    jq -c '.findings[]? | {titulo:(.category // "Achado"),dado:(.value // ""),url:(.sources[0] // "")}' "$file" 2>/dev/null >> "$CRAFTJS_FILE" ;;

                *-bird-final-findings.json)
                    jq -c --arg source "$fname" '.findings[]? + {_source_file:$source}' "$file" 2>/dev/null >> "$FINAL_FINDINGS_FILE" ;;

                *katana.json)
                    if command -v jq &>/dev/null; then
                        jq -r '.request.endpoint // empty' "$file" 2>/dev/null >> "$urls_raw"
                    fi ;;
            esac
        done
    done

    # Clean + dedupe + scope filter subdomains
    sed -i 's/ (FQDN)//g; s/(FQDN)//g; s/ (IPAddress)//g; s/(IPAddress)//g' "$subs_raw" 2>/dev/null
    sort -u "$subs_raw" | grep -v '^$' | grep '\.' | grep -v 'virustotal' | while IFS= read -r item; do is_in_scope "$item" && echo "$item"; done > "$SUBS_FILE" 2>/dev/null || true

    # Clean + scope filter URLs
    sort -u "$urls_raw" | grep -E '^https?://' | while IFS= read -r item; do is_in_scope "$item" && echo "$item"; done > "$URLS_FILE" 2>/dev/null || true

    # Clean IP map (dedupe)
    sort -u "$IP_MAP_FILE" -o "$IP_MAP_FILE" 2>/dev/null

    local nsubs=$(wc -l < "$SUBS_FILE" | tr -d ' ')
    local nurls=$(wc -l < "$URLS_FILE" | tr -d ' ')
    local nmaps=$(wc -l < "$IP_MAP_FILE" | tr -d ' ')
    log_success "Processados: $total_files arquivos"
    log_success "  → $nsubs subs, $nurls URLs, $nmaps mapeamentos IP"
}

# ============================================
# DNS VALIDATION + IP CORRELATION
# ============================================

validate_subdomains() {
    log_info "Validando subdomínios (DNS resolve + correlação IP)..."
    local validated="${TEMP_DIR}/validated_subs.txt"
    # Format: subdomain|status|ip
    > "$validated"

    local total=$(wc -l < "$SUBS_FILE" | tr -d ' ')
    local count=0

    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        count=$((count + 1))
        if (( count % 20 == 0 )); then
            log_info "  Validando: $count/$total..."
        fi

        local ip=""
        local status="inactive"

        # Try DNS lookup first
        local dns_result
        dns_result=$(host -W 2 "$sub" 2>/dev/null)
        if echo "$dns_result" | grep -q "has address"; then
            ip=$(echo "$dns_result" | grep "has address" | head -1 | awk '{print $NF}')
            status="active"
        fi

        # If no IP from DNS, check fierce/dnsenum mappings
        if [[ -z "$ip" ]]; then
            ip=$(grep -i "^${sub}|" "$IP_MAP_FILE" 2>/dev/null | head -1 | cut -d'|' -f2)
            # Also search without trailing dot variants
            if [[ -z "$ip" ]]; then
                ip=$(grep -i "^${sub}\.|" "$IP_MAP_FILE" 2>/dev/null | head -1 | cut -d'|' -f2)
            fi
        fi

        # Collect all IPs for this subdomain
        local all_ips="$ip"
        local extra_ips=$(grep -i "^${sub}|" "$IP_MAP_FILE" 2>/dev/null | cut -d'|' -f2 | sort -u | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$extra_ips" && "$extra_ips" != "$ip" ]]; then
            if [[ -n "$all_ips" ]]; then
                all_ips=$(echo -e "${all_ips}\n${extra_ips}" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
            else
                all_ips="$extra_ips"
            fi
        fi

        echo "${sub}|${status}|${all_ips}" >> "$validated"
    done < "$SUBS_FILE"

    local active=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | wc -l | tr -d ' ')
    local inactive=$(grep '|inactive|' "${TEMP_DIR}/validated_subs.txt" | wc -l | tr -d ' ')
    log_success "Validação: $active ativos, $inactive inativos (total: $total)"
}

# ============================================
# SHODAN: InternetDB (free) + Paid API (fallback)
# ============================================

query_shodan_ip() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1

    local cache_file="${SHODAN_CACHE}/${ip}.json"
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi

    # 1) Try paid Shodan API first if key is set (Prioritize as requested)
    if [[ -n "$SHODAN_API_KEY" ]]; then
        local result
        result=$(timeout 15 curl -sf "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}&minify=true" 2>/dev/null)
        if [[ $? -eq 0 && -n "$result" ]]; then
            # Convert paid API format to InternetDB-compatible format (with CVES)
            local converted
            converted=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    out={'ip':d.get('ip_str',''),'ports':d.get('ports',[]),'cpes':d.get('cpe',[]),'vulns':d.get('vulns',[]),'hostnames':d.get('hostnames',[])}
    for item in d.get('data',[]):
        prod=item.get('product','')
        if prod:
            cpe=f'cpe:/a:vendor:{prod.lower().replace(\" \",\"_\")}'
            if cpe not in out['cpes']: out['cpes'].append(cpe)
    print(json.dumps(out))
except: pass
" <<< "$result" 2>/dev/null)
            if [[ -n "$converted" ]]; then
                echo "$converted" > "$cache_file"
                echo "$converted"
                return 0
            fi
        fi
    fi

    # 2) Fallback to free InternetDB
    local result
    result=$(timeout 10 curl -sf "https://internetdb.shodan.io/${ip}" 2>/dev/null)
    if [[ $? -eq 0 && -n "$result" && "$result" != *"No information"* ]]; then
        echo "$result" > "$cache_file"
        echo "$result"
        return 0
    fi
    return 1
}

get_ports_services() {
    local ip="$1"
    [[ -z "$ip" ]] && echo "" && return

    local idb_data
    idb_data=$(query_shodan_ip "$ip" 2>/dev/null)
    if [[ -n "$idb_data" ]]; then
        python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    ports=d.get('ports',[])
    cpes=d.get('cpes',[])
    vulns=d.get('vulns',[])
    # Well-known port→service mapping
    svc={20:'ftp-data',21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',67:'dhcp',
         69:'tftp',80:'http',110:'pop3',111:'rpc',119:'nntp',123:'ntp',135:'msrpc',
         137:'netbios',139:'netbios',143:'imap',161:'snmp',162:'snmp-trap',179:'bgp',
         389:'ldap',443:'https',445:'smb',465:'smtps',514:'syslog',515:'printer',
         587:'submission',631:'ipp',636:'ldaps',873:'rsync',993:'imaps',995:'pop3s',
         1080:'socks',1433:'mssql',1434:'mssql',1521:'oracle',1883:'mqtt',
         2049:'nfs',2375:'docker',2376:'docker-tls',3000:'grafana',3306:'mysql',
         3389:'rdp',5432:'postgres',5672:'amqp',5900:'vnc',6379:'redis',
         6443:'k8s-api',7001:'weblogic',8000:'http-alt',8080:'http-proxy',
         8443:'https-alt',8888:'http-alt',9090:'prometheus',9200:'elasticsearch',
         9300:'elasticsearch',9922:'ssh-alt',11211:'memcached',15672:'rabbitmq-mgmt',
         27017:'mongodb',27018:'mongodb'}
    # Map CPEs to product names
    products={}
    for c in cpes:
        parts=c.split(':')
        if len(parts)>=5 and parts[4]:
            products[parts[4]]=True
    prods=list(products.keys())
    # Build port display with service names
    parts=[]
    for p in sorted(ports):
        name=svc.get(p,'')
        if name:
            parts.append(f'{p}/{name}')
        else:
            parts.append(str(p))
    result=', '.join(parts)
    if prods:
        result += ' | ' + ', '.join(prods[:3])
    if vulns:
        result += ' | ⚠ ' + str(len(vulns)) + ' CVEs'
    print(result)
except:
    print('')
" <<< "$idb_data"
    fi
}

enrich_with_shodan() {
    if [[ -n "$SHODAN_API_KEY" ]]; then
        log_info "Consultando Shodan (InternetDB + API paga como fallback)..."
    else
        log_info "Consultando Shodan InternetDB (sem API key — use SHODAN_API_KEY para fallback)..."
    fi
    local unique_ips="${TEMP_DIR}/unique_ips.txt"
    cut -d'|' -f3 "${TEMP_DIR}/validated_subs.txt" | tr ',' '\n' | sort -u | grep -v '^$' > "$unique_ips"

    local total=$(wc -l < "$unique_ips" | tr -d ' ')
    local count=0 found=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        count=$((count + 1))
        if (( count % 5 == 0 )); then
            log_info "  Shodan: $count/$total IPs..."
        fi
        if query_shodan_ip "$ip" > /dev/null 2>&1; then
            found=$((found + 1))
        fi
        sleep 0.3
    done < "$unique_ips"
    log_success "Shodan: $found/$total IPs com dados de portas/serviços"
}

# ============================================
# CSS + JS (same premium design)
# ============================================

generate_css() {
    cat > "${ASSETS_DIR}/style.css" << 'EOFCSS'
@import url('https://fonts.googleapis.com/css2?family=Urbanist:wght@500;600;700;800;900&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
:root{--primary:#ef4444;--primary-light:#f87171;--secondary:#dc2626;--success:#10b981;--warning:#f59e0b;--danger:#ef4444;--info:#38bdf8;--dark:#1e293b;--darker:#0f172a;--darkest:#0b1120;--light:#f8fafc;--gray:#64748b;--glass:rgba(30,41,59,0.52);--glass-border:rgba(255,255,255,0.10);--glow:rgba(239,68,68,0.14)}
body{font-family:'Inter',system-ui,sans-serif;background-color:var(--darker);background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px),radial-gradient(circle at 80% 10%,rgba(56,189,248,.07),transparent 34%);background-size:50px 50px,50px 50px,auto;color:var(--light);min-height:100vh;line-height:1.6}
h1,h2,h3,h4{font-family:'Urbanist','Inter',sans-serif}
.container{max-width:1400px;margin:0 auto;padding:2rem}
nav{background:rgba(15,23,42,0.9);backdrop-filter:blur(16px);border-bottom:1px solid var(--glass-border);padding:0.75rem 0;position:sticky;top:0;z-index:1000;box-shadow:0 4px 30px rgba(0,0,0,0.3)}
nav .container{display:flex;justify-content:space-between;align-items:center;padding:0 2rem}
nav h1{font-size:1.25rem;font-weight:900;letter-spacing:.08em;color:#fff;white-space:nowrap}nav h1 span{color:var(--primary);font-family:'JetBrains Mono',monospace;font-size:.82rem;letter-spacing:0}
nav .nav-links{display:flex;gap:0.3rem;flex-wrap:wrap}
nav .nav-links a{color:#94a3b8;text-decoration:none;padding:0.4rem 0.75rem;border-radius:0.5rem;transition:all 0.3s;font-size:0.82rem;font-weight:500;border:1px solid transparent}
nav .nav-links a:hover,nav .nav-links a.active{color:white;background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,.32);transform:translateY(-1px)}
.card{background:var(--glass);backdrop-filter:blur(20px) saturate(180%);border:1px solid var(--glass-border);border-radius:1rem;padding:1.5rem;margin-bottom:1.5rem;transition:all 0.4s;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;width:100%;height:1px;background:linear-gradient(90deg,transparent,rgba(99,102,241,0.3),transparent)}
.card:hover{border-color:rgba(99,102,241,0.3);box-shadow:0 8px 32px var(--glow)}
.hero-card{background:linear-gradient(135deg,rgba(239,68,68,.10),rgba(56,189,248,.035));border-left:3px solid var(--primary);padding:2.25rem}.hero-card .eyebrow{font:600 .72rem 'JetBrains Mono',monospace;color:var(--primary);letter-spacing:.14em;text-transform:uppercase}.hero-card h2{font-size:clamp(2rem,5vw,4rem);line-height:1.05;margin:.55rem 0}.hero-card p{color:#cbd5e1;max-width:760px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1.25rem;margin-bottom:2rem}
.stat-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:1rem;padding:1.5rem;text-align:center;transition:all 0.4s;position:relative;overflow:hidden}
.stat-card::after{content:'';position:absolute;bottom:0;left:0;width:100%;height:3px;background:linear-gradient(90deg,var(--primary),var(--secondary));opacity:0;transition:opacity 0.3s}
.stat-card:hover::after{opacity:1}
.stat-card:hover{transform:translateY(-4px);box-shadow:0 12px 40px var(--glow)}
.stat-icon{font-size:1.5rem;margin-bottom:0.5rem}
.stat-card .stat-number{font-size:2.5rem;font-weight:700;background:linear-gradient(135deg,#c7d2fe,#e0e7ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:0.25rem;line-height:1.2}
.stat-card .stat-label{color:#94a3b8;font-size:0.8rem;text-transform:uppercase;letter-spacing:1.5px;font-weight:500}
.stat-card-link{text-decoration:none;color:inherit;display:block}
.table-container{overflow-x:auto;border-radius:1rem;background:var(--glass);border:1px solid var(--glass-border);backdrop-filter:blur(20px)}
table{width:100%;border-collapse:collapse}
thead{background:rgba(99,102,241,0.08);border-bottom:1px solid var(--glass-border)}
thead th{padding:0.85rem 1rem;text-align:left;font-weight:600;color:#c7d2fe;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.8px;white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(30,41,59,0.5);transition:all 0.2s}
tbody tr:hover{background:rgba(99,102,241,0.05)}
tbody td{padding:0.75rem 1rem;color:var(--light);font-size:0.85rem;vertical-align:middle}
.badge-active{display:inline-flex;align-items:center;gap:0.3rem;padding:0.2rem 0.6rem;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);color:#6ee7b7;border-radius:1rem;font-size:0.72rem;font-weight:600}
.badge-inactive{display:inline-flex;align-items:center;gap:0.3rem;padding:0.2rem 0.6rem;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.25);color:#fca5a5;border-radius:1rem;font-size:0.72rem;font-weight:600}
.link-btn{display:inline-block;padding:0.3rem 0.55rem;margin:0.1rem;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);color:#a5b4fc;text-decoration:none;border-radius:0.4rem;font-size:0.72rem;transition:all 0.3s;font-weight:500;white-space:nowrap}
.link-btn:hover{background:rgba(99,102,241,0.25);transform:translateY(-1px);color:white}
.link-btn.github{background:rgba(36,41,46,0.3);border-color:rgba(255,255,255,0.15);color:#e6edf3}
.link-btn.gitlab{background:rgba(226,67,41,0.12);border-color:rgba(226,67,41,0.25);color:#fc6d26}
.link-btn.bitbucket{background:rgba(0,82,204,0.12);border-color:rgba(0,82,204,0.25);color:#4c9aff}
.link-btn.fofa{background:rgba(245,158,11,0.12);border-color:rgba(245,158,11,0.25);color:#fcd34d}
.link-btn.censys{background:rgba(59,130,246,0.12);border-color:rgba(59,130,246,0.25);color:#93c5fd}
.link-btn.shodan{background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,0.25);color:#fca5a5}
.filter-bar{display:flex;gap:0.75rem;margin-bottom:1.25rem;flex-wrap:wrap;align-items:center}
.filter-bar input,.filter-bar select{padding:0.7rem 1rem;background:rgba(2,6,23,0.8);border:1px solid var(--glass-border);border-radius:0.5rem;color:var(--light);font-size:0.88rem;transition:all 0.3s;flex:1;min-width:200px;font-family:'Inter',system-ui,sans-serif}
.filter-bar input:focus,.filter-bar select:focus{outline:none;border-color:var(--primary-light);box-shadow:0 0 0 3px rgba(99,102,241,0.15)}
.filter-bar input::placeholder{color:#475569}
.filter-bar select option{background:#0f172a}
code{background:rgba(0,0,0,0.4);padding:0.15rem 0.45rem;border-radius:0.3rem;font-family:'JetBrains Mono','Courier New',monospace;font-size:0.78rem;color:#67e8f9;border:1px solid rgba(103,232,249,0.1)}
.export-btn{padding:0.6rem 1rem;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);border-radius:0.5rem;color:#6ee7b7;cursor:pointer;font-size:0.82rem;transition:all 0.3s;font-family:'Inter',system-ui,sans-serif;font-weight:500;white-space:nowrap}
.export-btn:hover{background:rgba(16,185,129,0.25);transform:translateY(-1px)}
.llm-badge{display:inline-block;padding:0.2rem 0.6rem;background:linear-gradient(135deg,#f59e0b,#d97706);color:white!important;border-radius:1rem;font-size:0.7rem;font-weight:600;margin-left:0.5rem;-webkit-text-fill-color:white!important}
.ports-cell{font-size:0.72rem;color:#94a3b8;max-width:250px;line-height:1.5}
.actions-cell{white-space:nowrap;position:relative}
.action-groups{display:flex;gap:0.3rem;flex-wrap:nowrap}
.dropdown{position:relative;display:inline-block}
.dropdown-toggle{padding:0.35rem 0.6rem;border-radius:0.4rem;font-size:0.72rem;font-weight:600;cursor:pointer;border:1px solid;transition:all 0.3s;font-family:'Inter',system-ui,sans-serif;white-space:nowrap}
.dropdown-toggle:hover{transform:translateY(-1px)}
.ip-toggle{background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,0.3);color:#fca5a5}
.ip-toggle:hover{background:rgba(239,68,68,0.25)}
.domain-toggle{background:rgba(59,130,246,0.12);border-color:rgba(59,130,246,0.3);color:#93c5fd}
.domain-toggle:hover{background:rgba(59,130,246,0.25)}
.git-toggle{background:rgba(16,185,129,0.12);border-color:rgba(16,185,129,0.3);color:#6ee7b7}
.git-toggle:hover{background:rgba(16,185,129,0.25)}
.fuzz-toggle{background:rgba(251,146,60,0.12);border-color:rgba(251,146,60,0.3);color:#fdba74}
.fuzz-toggle:hover{background:rgba(251,146,60,0.25)}
.dropdown-menu{display:none;position:absolute;top:100%;right:0;min-width:220px;background:rgba(15,23,42,0.95);backdrop-filter:blur(20px) saturate(180%);border:1px solid rgba(99,102,241,0.2);border-radius:0.6rem;padding:0.4rem 0;z-index:100;box-shadow:0 8px 32px rgba(0,0,0,0.5);margin-top:0.3rem;max-height:350px;overflow-y:auto}
.dropdown.open .dropdown-menu{display:block;animation:fadeInUp 0.2s ease}
.dropdown-menu a{display:block;padding:0.4rem 0.8rem;color:#e2e8f0;text-decoration:none;font-size:0.75rem;transition:all 0.2s;border-left:2px solid transparent}
.dropdown-menu a:hover{background:rgba(99,102,241,0.12);color:white;border-left-color:var(--primary-light)}
.dropdown-label{padding:0.3rem 0.8rem;color:#64748b;font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-top:1px solid rgba(30,41,59,0.8);margin-top:0.2rem}
.dropdown-label:first-child{border-top:none;margin-top:0}
.dropdown-menu-wide{min-width:320px}
.cmd-copy{padding:0.4rem 0.8rem;color:#94a3b8;font-size:0.72rem;font-family:'JetBrains Mono',monospace;cursor:pointer;transition:all 0.2s;border-left:2px solid transparent;position:relative}
.cmd-copy:hover{background:rgba(251,146,60,0.12);color:#fdba74;border-left-color:#fb923c}
.cmd-copy.copied{background:rgba(16,185,129,0.15);color:#6ee7b7;border-left-color:#10b981}
.cmd-copy.copied::after{content:'✅ Copied!';position:absolute;left:50%;bottom:calc(100% + 4px);transform:translateX(-50%);font-size:0.65rem;color:#6ee7b7;background:#1e293b;padding:2px 8px;border-radius:4px;border:1px solid rgba(110,231,183,0.3);white-space:nowrap;z-index:10}
.ip-cell code{display:block;margin:1px 0}
.port-chart{display:grid;gap:.85rem}.port-row{display:grid;grid-template-columns:115px 1fr 70px;gap:1rem;align-items:center}.port-label{font:600 .78rem 'JetBrains Mono',monospace;color:#e2e8f0}.port-track{height:12px;border-radius:2px;background:rgba(255,255,255,.06);overflow:hidden}.port-bar{height:100%;min-width:4px;background:linear-gradient(90deg,var(--info),#0ea5e9);box-shadow:0 0 14px rgba(56,189,248,.24)}.port-row.sensitive .port-bar{background:linear-gradient(90deg,var(--primary),#dc2626);box-shadow:0 0 14px rgba(239,68,68,.26)}.port-count{font:600 .72rem 'JetBrains Mono',monospace;color:#94a3b8;text-align:right}
.scope-meta{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1.2rem}.scope-pill{border:1px solid rgba(56,189,248,.25);background:rgba(56,189,248,.07);color:#7dd3fc;border-radius:3px;padding:.35rem .65rem;font:500 .72rem 'JetBrains Mono',monospace}
.ai-nav.is-disabled{display:none}.ai-nav.is-pending{pointer-events:none;opacity:.65;border-style:dashed}.ai-nav.is-ready{color:#fff;border-color:rgba(56,189,248,.35);background:rgba(56,189,248,.08)}
.finding-card{border-left:3px solid #64748b}.finding-card.severity-critical,.finding-card.severity-high{border-left-color:#ef4444}.finding-card.severity-medium{border-left-color:#f59e0b}.finding-card.severity-low{border-left-color:#38bdf8}.finding-meta{display:flex;gap:.5rem;flex-wrap:wrap;margin:.55rem 0}.finding-meta span{font:500 .7rem 'JetBrains Mono',monospace;color:#94a3b8;border:1px solid rgba(255,255,255,.09);padding:.2rem .45rem;border-radius:3px}.evidence-block{white-space:pre-wrap;word-break:break-word;background:#020617;border:1px solid rgba(56,189,248,.13);padding:.85rem;border-radius:4px;color:#cbd5e1;font:.74rem/1.65 'JetBrains Mono',monospace}.evidence-block a{display:inline-block;max-width:100%;margin:.12rem 0;padding:.16rem .38rem;border-left:2px solid #f59e0b;border-radius:3px;background:rgba(245,158,11,.11);color:#fde68a;text-decoration:none;overflow-wrap:anywhere;word-break:break-word}.evidence-block a:hover{background:rgba(245,158,11,.2);color:#fff7d6}.api-endpoint-link{display:inline-block;max-width:100%;padding:.24rem .42rem;border:1px solid rgba(52,211,153,.3);border-radius:4px;background:rgba(16,185,129,.1);color:#a7f3d0;text-decoration:none;font:500 .74rem/1.55 'JetBrains Mono',monospace;overflow-wrap:anywhere;word-break:break-word}.api-endpoint-link:hover{background:rgba(16,185,129,.19);border-color:rgba(110,231,183,.55);color:#ecfdf5}.empty-state{text-align:center;padding:4rem 1rem;color:#64748b}.section-number{font:700 .75rem 'JetBrains Mono',monospace;color:var(--primary);letter-spacing:.12em}.quick-links{display:flex;gap:.55rem;flex-wrap:wrap;margin-top:1rem}.quick-links a{color:#cbd5e1;text-decoration:none;border-bottom:1px solid rgba(239,68,68,.4);font:600 .75rem 'JetBrains Mono',monospace}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.card,.stat-card-link,.table-container{animation:fadeInUp 0.5s ease forwards}
@media(max-width:768px){nav .container{flex-direction:column;gap:0.75rem}.stats-grid{grid-template-columns:1fr 1fr}.container{padding:1rem}table{font-size:0.75rem}.port-row{grid-template-columns:90px 1fr 55px}}
EOFCSS
}

generate_js() {
    cat > "${ASSETS_DIR}/script.js" << 'EOFJS'
function initFilters(){
    const s=document.getElementById('searchInput'),
          f=document.getElementById('filterStatus'),
          t=document.querySelector('table tbody');
    if(!t)return;
    const rows=Array.from(t.rows);
    function doFilter(){
        const st=s?s.value.toLowerCase():'';
        const fv=f?f.value:'';
        let vis=0;
        rows.forEach(r=>{
            const txt=r.textContent.toLowerCase();
            const isActive=r.querySelector('.badge-active')!==null;
            const statusMatch=!fv||(fv==='active'&&isActive)||(fv==='inactive'&&!isActive);
            const show=txt.includes(st)&&statusMatch;
            r.style.display=show?'':'none';
            if(show)vis++;
        });
        const c=document.getElementById('visibleCount');
        if(c)c.textContent=vis;
    }
    if(s)s.addEventListener('input',doFilter);
    if(f)f.addEventListener('change',doFilter);
}
function exportCSV(){
    const t=document.querySelector('table');if(!t)return;
    let csv=[];
    t.querySelectorAll('tr').forEach(r=>{
        if(r.style.display==='none')return;
        const cols=r.querySelectorAll('td,th');
        csv.push(Array.from(cols).map(c=>'"'+c.textContent.replace(/"/g,'""').trim()+'"').join(','));
    });
    const b=new Blob([csv.join('\n')],{type:'text/csv'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='w-brid-export.csv';a.click();
}
function exportJSON(){
    const t=document.querySelector('table');if(!t)return;
    const h=Array.from(t.querySelectorAll('thead th')).map(h=>h.textContent.trim());
    const d=[];
    t.querySelectorAll('tbody tr').forEach(r=>{
        if(r.style.display==='none')return;
        const o={};r.querySelectorAll('td').forEach((td,i)=>{if(h[i])o[h[i]]=td.textContent.trim()});d.push(o);
    });
    const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='w-brid-export.json';a.click();
}
document.addEventListener('DOMContentLoaded',function(){
    initFilters();
    const ai=window.WBRID_AI_STATUS||{status:'disabled'};
    document.querySelectorAll('[data-ai-link]').forEach(link=>{
        link.classList.remove('is-disabled','is-pending','is-ready');
        if(ai.status==='ready'){link.classList.add('is-ready');link.href='ai-findings.html';link.textContent='IA Findings'}
        else if(ai.status==='processing'||ai.status==='pending'){link.classList.add('is-pending');link.removeAttribute('href');link.textContent='IA Findings';link.title='Análise em processamento'}
        else if(ai.status==='error'){link.classList.add('is-pending');link.removeAttribute('href');link.textContent='IA Findings';link.title='Falha na análise IA'}
        else{link.classList.add('is-disabled')}
    });
    // Dropdown toggle
    document.addEventListener('click',function(e){
        const toggle=e.target.closest('.dropdown-toggle');
        if(toggle){
            e.stopPropagation();
            const dd=toggle.parentElement;
            const wasOpen=dd.classList.contains('open');
            document.querySelectorAll('.dropdown.open').forEach(d=>d.classList.remove('open'));
            if(!wasOpen) dd.classList.add('open');
            return;
        }
        if(!e.target.closest('.dropdown-menu')){
            document.querySelectorAll('.dropdown.open').forEach(d=>d.classList.remove('open'));
        }
    });
    // Counter animation
    document.querySelectorAll('.stat-number[data-count]').forEach(el=>{
        const target=parseInt(el.dataset.count);if(isNaN(target)||target===0)return;
        let cur=0;const step=Math.max(1,Math.ceil(target/30));
        const timer=setInterval(()=>{cur+=step;if(cur>=target){cur=target;clearInterval(timer)}el.textContent=cur.toLocaleString()},30);
    });
});
EOFJS
}

# ============================================
# NAV
# ============================================

generate_nav() {
    local current="${1:-index}"
    cat <<EOFNAV
    <script src="assets/ai-status.js"></script>
    <nav>
        <div class="container">
            <h1>W-BRID <span>— ${PRIMARY_DOMAIN:-ESCOPO}</span></h1>
            <div class="nav-links">
                <a href="index.html" $([ "$current" = "index" ] && echo 'class="active"')>Dashboard</a>
                <a href="subdomains.html" $([ "$current" = "subdomains" ] && echo 'class="active"')>Subdomínios</a>
                <a href="brid-craftjs.html" $([ "$current" = "brid" ] && echo 'class="active"')>Bird-Craft</a>
                <a data-ai-link class="ai-nav is-disabled">IA Findings</a>
                <a href="final-findings.html" $([ "$current" = "final" ] && echo 'class="active"')>Final Findings</a>
                <a href="urls.html" $([ "$current" = "urls" ] && echo 'class="active"')>URLs</a>
                <a href="tree.html" $([ "$current" = "tree" ] && echo 'class="active"')>Tree</a>
                <a href="dns.html" $([ "$current" = "dns" ] && echo 'class="active"')>DNS</a>
            </div>
        </div>
    </nav>
EOFNAV
}

# ============================================
# PAGE: INDEX
# ============================================


generate_index() {
    local active inactive unique_ips total_urls port_chart
    active=$(awk -F'|' '$2=="active"{count++} END{print count+0}' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null)
    inactive=$(awk -F'|' '$2=="inactive"{count++} END{print count+0}' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null)
    unique_ips=$(awk -F'|' '{print $3}' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sort -u | wc -l | tr -d '[:space:]')
    total_urls=$(wc -l < "$URLS_FILE" 2>/dev/null | tr -d '[:space:]')
    active=${active:-0}; inactive=${inactive:-0}; unique_ips=${unique_ips:-0}; total_urls=${total_urls:-0}
    port_chart=$(SHODAN_CACHE="$SHODAN_CACHE" VALIDATED_SUBS="${TEMP_DIR}/validated_subs.txt" python3 <<'PYEOF'
import glob, html, json, os
from collections import defaultdict

cache_dir = os.environ["SHODAN_CACHE"]
validated = os.environ["VALIDATED_SUBS"]
ip_hosts = defaultdict(set)
try:
    for line in open(validated, encoding="utf-8", errors="replace"):
        parts = line.strip().split("|")
        if len(parts) >= 3:
            for ip in parts[2].split(","):
                if ip.strip():
                    ip_hosts[ip.strip()].add(parts[0])
except OSError:
    pass

port_hosts = defaultdict(set)
for filename in glob.glob(os.path.join(cache_dir, "*.json")):
    ip = os.path.basename(filename)[:-5]
    try:
        data = json.load(open(filename, encoding="utf-8"))
    except (OSError, ValueError):
        continue
    hosts = ip_hosts.get(ip) or {ip}
    for raw_port in data.get("ports", []):
        try:
            port_hosts[int(raw_port)].update(hosts)
        except (TypeError, ValueError):
            pass

if port_hosts:
    services = {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1433:"MSSQL",2375:"DOCKER",3306:"MYSQL",3389:"RDP",5432:"POSTGRES",5900:"VNC",6379:"REDIS",8080:"HTTP-ALT",8443:"HTTPS-ALT",9200:"ELASTIC",27017:"MONGODB"}
    sensitive = {21,22,23,445,1433,2375,3306,3389,5432,5900,6379,9200,27017}
    rows = sorted(port_hosts.items(), key=lambda item: (-len(item[1]), item[0]))[:5]
    maximum = max(len(hosts) for _, hosts in rows) or 1
    print('<section class="card"><span class="section-number">[01] EXPOSIÇÃO DE REDE</span><h3>Portas mais recorrentes</h3><div class="port-chart" style="margin-top:1.25rem">')
    for port, hosts in rows:
        service = services.get(port, "TCP")
        width = max(4, round(len(hosts) * 100 / maximum))
        klass = "port-row sensitive" if port in sensitive else "port-row"
        title = html.escape(", ".join(sorted(hosts)[:12]), quote=True)
        print(f'<div class="{klass}" title="{title}"><div class="port-label">{port}/{service}</div><div class="port-track"><div class="port-bar" style="width:{width}%"></div></div><div class="port-count">{len(hosts)} host(s)</div></div>')
    print('</div><div class="quick-links"><a href="subdomains.html">ver infraestrutura detalhada →</a></div></section>')
PYEOF
)
    cat > "${DASHBOARD_DIR}/index.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${REPORT_TITLE}</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "index")
<main class="container">
    <section class="card hero-card">
        <span class="eyebrow">superfície autorizada</span>
        <h2>${PRIMARY_DOMAIN:-ESCOPO}</h2>
        <p>Relatório técnico consolidado de reconhecimento e análise da superfície web.</p>
        <div class="scope-meta"><span class="scope-pill">W-BRID</span><span class="scope-pill">gerado $(date '+%Y-%m-%d %H:%M')</span></div>
    </section>
    <section class="stats-grid">
        <a href="subdomains.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon" style="color:#34d399">●</div><div class="stat-number" data-count="$active">$active</div><div class="stat-label">Subdomínios ativos</div></div></a>
        <a href="subdomains.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon" style="color:#f87171">●</div><div class="stat-number" data-count="$inactive">$inactive</div><div class="stat-label">Subdomínios inativos</div></div></a>
        <a href="subdomains.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon" style="color:#38bdf8">⌁</div><div class="stat-number" data-count="$unique_ips">$unique_ips</div><div class="stat-label">IPs únicos</div></div></a>
        <a href="urls.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon" style="color:#f59e0b">↗</div><div class="stat-number" data-count="$total_urls">$total_urls</div><div class="stat-label">URLs coletadas</div></div></a>
    </section>
    ${port_chart}
</main>
<script src="assets/script.js"></script></body></html>
EOFHTML
}

# ============================================
# PAGE: UNIFIED SUBDOMAINS
# ============================================

generate_subdomains_page() {
    local active=$(awk -F'|' '$2=="active"{count++} END{print count+0}' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null)
    local inactive=$(awk -F'|' '$2=="inactive"{count++} END{print count+0}' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null)
    local total=$(( ${active:-0} + ${inactive:-0} ))

    cat > "${DASHBOARD_DIR}/subdomains.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${REPORT_TITLE}</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "subdomains")
<div class="container">
    <div class="card">
        <h2>🌐 Subdomínios <span class="llm-badge">📊 Auto</span></h2>
        <p>Total: <strong id="visibleCount">$total</strong> subdomínios • <span style="color:#6ee7b7">$active ativos</span> • <span style="color:#fca5a5">$inactive inativos</span>$([ -n "$SHODAN_API_KEY" ] && echo " • 🔒 Shodan API ativa")</p>
    </div>
    <div class="filter-bar">
        <input type="text" id="searchInput" placeholder="🔍 Buscar subdomínio, IP, porta...">
        <select id="filterStatus">
            <option value="">Todos</option>
            <option value="active">🟢 Ativos</option>
            <option value="inactive">🔴 Inativos</option>
        </select>
        <button class="export-btn" onclick="exportCSV()">📄 CSV</button>
        <button class="export-btn" onclick="exportJSON()">📋 JSON</button>
    </div>
    <div class="table-container">
        <table>
            <thead><tr>
                <th>#</th>
                <th>Status</th>
                <th>Domínio / Subdomínio</th>
                <th>IPs Relacionados</th>
                <th>Infraestrutura IA</th>
                <th>Portas + Serviços</th>
                <th>Ações</th>
            </tr></thead>
            <tbody>
EOFHTML

    local idx=1
    # Sort: active first, then alphabetical
    sort -t'|' -k2,2 -k1,1 "${TEMP_DIR}/validated_subs.txt" | while IFS='|' read -r sub status ips; do
        [[ -z "$sub" ]] && continue

        # Status badge
        local badge
        if [[ "$status" == "active" ]]; then
            badge='<span class="badge-active">🟢 Ativo</span>'
        else
            badge='<span class="badge-inactive">🔴 Inativo</span>'
        fi

        # IPs column
        local ip_html="<span style='color:#475569'>—</span>"
        if [[ -n "$ips" ]]; then
            ip_html=""
            IFS=',' read -ra ip_arr <<< "$ips"
            for ip in "${ip_arr[@]}"; do
                [[ -z "$ip" ]] && continue
                ip_html+="<code>$ip</code> "
            done
        fi

        # Ports/Services (from Shodan InternetDB — query ALL IPs, merge results)
        local ports_html="<span style='color:#475569'>—</span>"
        if [[ -n "$ips" ]]; then
            local all_ports_data=""
            IFS=',' read -ra check_ips <<< "$ips"
            for check_ip in "${check_ips[@]}"; do
                [[ -z "$check_ip" ]] && continue
                local pd=$(get_ports_services "$check_ip")
                if [[ -n "$pd" ]]; then
                    if [[ -n "$all_ports_data" ]]; then
                        all_ports_data+="<br><small style='color:#475569'>[$check_ip]</small> $pd"
                    else
                        all_ports_data="$pd"
                    fi
                fi
            done
            if [[ -n "$all_ports_data" ]]; then
                ports_html="<span class='ports-cell'>$all_ports_data</span>"
            fi
        fi

        # Encode for URLs
        local sub_enc=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$sub'))" 2>/dev/null || echo "$sub")

        # Build grouped dropdown menus
        local actions="<div class='action-groups'>"

        # === IP GROUP ===
        if [[ -n "$ips" ]]; then
            local first_ip=$(echo "$ips" | cut -d',' -f1)
            local ib64=$(echo -n "ip=\"$first_ip\"" | base64 -w0 2>/dev/null)
            actions+="<div class='dropdown'>"
            actions+="<button class='dropdown-toggle ip-toggle'>⚙️ IP</button>"
            actions+="<div class='dropdown-menu'>"
            actions+="<div class='dropdown-label'>Busca por IP</div>"
            actions+="<a href=\"https://www.shodan.io/host/$first_ip\" target=\"_blank\">🔴 Shodan</a>"
            actions+="<a href=\"https://search.censys.io/hosts/$first_ip\" target=\"_blank\">🔵 Censys</a>"
            actions+="<a href=\"https://en.fofa.info/result?qbase64=$ib64\" target=\"_blank\">🟡 FOFA</a>"
            actions+="<div class='dropdown-label'>Dorks IP</div>"
            actions+="<a href=\"https://www.shodan.io/search?query=net:$first_ip/24\" target=\"_blank\">Shodan: net:$first_ip/24</a>"
            actions+="<a href=\"https://www.shodan.io/search?query=ip:$first_ip+port:22,80,443,3389\" target=\"_blank\">Shodan: common ports</a>"
            actions+="<a href=\"https://www.shodan.io/search?query=ip:$first_ip+vuln:CVE\" target=\"_blank\">Shodan: CVEs</a>"
            actions+="<a href=\"https://www.google.com/search?q=%22$first_ip%22\" target=\"_blank\">Google: \"$first_ip\"</a>"
            actions+="<a href=\"https://search.censys.io/search?resource=hosts&q=ip:$first_ip+and+services.port:%2A\" target=\"_blank\">Censys: all services</a>"
            actions+="<div class='dropdown-label'>Comandos IP</div>"
            actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"nmap -sS -p- --open -Pn $first_ip -oN nmap-ss-allp-$first_ip\">📋 Nmap Full Stealth</div>"
            actions+="</div></div>"
        fi

        # === DOMAIN GROUP ===
        local db64=$(echo -n "domain=\"$sub\"" | base64 -w0 2>/dev/null)
        actions+="<div class='dropdown'>"
        actions+="<button class='dropdown-toggle domain-toggle'>🌐 Dom</button>"
        actions+="<div class='dropdown-menu'>"
        actions+="<div class='dropdown-label'>Busca por Domínio</div>"
        actions+="<a href=\"https://www.shodan.io/search?query=hostname:$sub_enc\" target=\"_blank\">🔴 Shodan</a>"
        actions+="<a href=\"https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=$sub_enc\" target=\"_blank\">🔵 Censys</a>"
        actions+="<a href=\"https://en.fofa.info/result?qbase64=$db64\" target=\"_blank\">🟡 FOFA</a>"
        actions+="<div class='dropdown-label'>Dorks Domínio</div>"
        actions+="<a href=\"https://www.shodan.io/search?query=ssl.cert.subject.CN:\&quot;$sub_enc\&quot;\" target=\"_blank\">Shodan: SSL cert CN</a>"
        actions+="<a href=\"https://www.shodan.io/search?query=http.title:\&quot;$sub_enc\&quot;\" target=\"_blank\">Shodan: HTTP title</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc\" target=\"_blank\">Google: site:$sub</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc+filetype:pdf+OR+filetype:xls+OR+filetype:doc\" target=\"_blank\">Google: docs</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc+inurl:login+OR+inurl:admin+OR+inurl:painel\" target=\"_blank\">Google: login pages</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc+inurl:api+OR+inurl:swagger+OR+inurl:graphql\" target=\"_blank\">Google: APIs</a>"
        actions+="<a href=\"https://www.google.com/search?q=%22$sub_enc%22+password+OR+senha+OR+secret+OR+token\" target=\"_blank\">Google: leaked creds</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:pastebin.com+OR+site:ghostbin.co+%22$sub_enc%22\" target=\"_blank\">Google: pastes</a>"
        actions+="</div></div>"

        # === GIT GROUP ===
        actions+="<div class='dropdown'>"
        actions+="<button class='dropdown-toggle git-toggle'>💻 GIT</button>"
        actions+="<div class='dropdown-menu'>"
        actions+="<div class='dropdown-label'>Code Search</div>"
        actions+="<a href=\"https://github.com/search?q=${sub_enc}&type=code\" target=\"_blank\">GitHub Code</a>"
        actions+="<a href=\"https://gitlab.com/search?search=${sub_enc}&nav_source=navbar\" target=\"_blank\">GitLab</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:bitbucket.org+%22${sub_enc}%22\" target=\"_blank\">Bitbucket</a>"
        actions+="<div class='dropdown-label'>Git Dorks</div>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+password+OR+secret+OR+token&type=code\" target=\"_blank\">GitHub: secrets</a>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+filename:.env+OR+filename:.yml+OR+filename:.conf&type=code\" target=\"_blank\">GitHub: configs</a>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+filename:id_rsa+OR+filename:id_dsa+OR+filename:.pem&type=code\" target=\"_blank\">GitHub: keys</a>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+AKIA+OR+aws_secret+OR+api_key&type=code\" target=\"_blank\">GitHub: API keys</a>"
        actions+="</div></div>"

        # === FUZZ GROUP ===
        actions+="<div class='dropdown'>"
        actions+="<button class='dropdown-toggle fuzz-toggle'>🔍 Fuzz</button>"
        actions+="<div class='dropdown-menu dropdown-menu-wide'>"
        actions+="<div class='dropdown-label'>Fuzzing Commands</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"gobuster dir -u https://$sub/ -w /usr/share/dirb/wordlists/big.txt -k -t 100 -e --no-error -r -o fuzz-gobuster-$sub -a Mozilla/5.0 --exclude-length 123456 -x php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log\">gobuster</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"feroxbuster --url https://$sub/ --methods GET,POST -r -A -w /usr/share/dirb/wordlists/big.txt -o fuzz-feroxbuster-$sub -x php bkp old txt xml cgi pdf html htm asp aspx pl sql js png jpg jpeg config sh cfm zip log\">feroxbuster</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"dirsearch -u https://$sub/ --crawl --full-url -t 1 --user-agent Mozilla/5.0 -e php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log -o fuzz-dirsearch-$sub\">dirsearch</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"ffuf -u https://$sub/FUZZ -w /usr/share/dirb/wordlists/big.txt -c -t 100 -e .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.zip,.log -o fuzz-ffuf-$sub.html -of html\">ffuf</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"dirb https://$sub/ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -a KidMan -X .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.sh,.cfm,.zip,.log -o fuzz-dirb-$sub\">dirb</div>"
        actions+="</div></div>"

        # === EXPLORE GROUP (port-based commands/links) ===
        if [[ -n "$ips" ]]; then
            local first_ip=$(echo "$ips" | cut -d',' -f1)
            local explore_items=""
            explore_items=$(python3 -c "
import json,os,html as h
ip = '$first_ip'
sub = '$sub'
cache = os.path.join('${SHODAN_CACHE}', ip + '.json')
port_map = {
    21:  ('FTP',  'ftp://SUB:21', 'curl -s ftp://SUB:21/ --user anonymous:anonymous -m 10'),
    22:  ('SSH',  'ssh://SUB:22', 'ssh -o StrictHostKeyChecking=no SUB -p 22'),
    23:  ('Telnet', 'telnet://SUB:23', 'telnet SUB 23'),
    25:  ('SMTP', None, 'nmap -sV -p 25 --script smtp-commands,smtp-enum-users IP'),
    53:  ('DNS',  None, 'dig @IP SUB ANY'),
    80:  ('HTTP', 'http://SUB:80', 'curl -sI http://SUB:80/ -m 10'),
    110: ('POP3', None, 'nmap -sV -p 110 --script pop3-capabilities IP'),
    143: ('IMAP', None, 'nmap -sV -p 143 --script imap-capabilities IP'),
    443: ('HTTPS','https://SUB:443', 'curl -sI https://SUB:443/ -m 10 -k'),
    445: ('SMB',  None, 'smbclient -L //IP/ -N'),
    993: ('IMAPS',None, 'openssl s_client -connect IP:993'),
    995: ('POP3S',None, 'openssl s_client -connect IP:995'),
    1433:('MSSQL',None, 'nmap -sV -p 1433 --script ms-sql-info IP'),
    3306:('MySQL',None, 'mysql -h IP -u root --connect-timeout=5'),
    3389:('RDP',  None, 'nmap -p 3389 --script rdp-ntlm-info IP'),
    5432:('PgSQL',None, 'psql -h IP -U postgres -l'),
    5900:('VNC',  None, 'nmap -sV -p 5900 --script vnc-info IP'),
    6379:('Redis',None, 'redis-cli -h IP ping'),
    8080:('HTTP', 'http://SUB:8080', 'curl -sI http://SUB:8080/ -m 10'),
    8443:('HTTPS','https://SUB:8443', 'curl -sI https://SUB:8443/ -m 10 -k'),
    9200:('Elastic',None, 'curl -s http://IP:9200/ -m 10'),
    27017:('MongoDB',None,'mongosh --host IP --port 27017'),
}
try:
    with open(cache) as f:
        data = json.load(f)
    ports = data.get('ports', [])
except: ports = []
if not ports:
    print('')
else:
    items = []
    items.append(\"<div class='dropdown-label'>Portas Abertas — Links e Comandos</div>\")
    for p in sorted(ports):
        info = port_map.get(p, (f'Port {p}', None, f'nmap -sV -p {p} IP'))
        svc, url_tpl, cmd_tpl = info
        cmd = cmd_tpl.replace('SUB', sub).replace('IP', ip)
        esc_cmd = h.escape(cmd, quote=True)
        line = f\"<div style='display:flex;align-items:center;gap:0.5rem;padding:0.3rem 0.5rem'>\"
        line += f\"<span style='color:#818cf8;min-width:50px;font-size:0.7rem'>{p}/{svc}</span>\"
        if url_tpl:
            url = url_tpl.replace('SUB', sub)
            line += f\"<a href='{url}' target='_blank' style='color:#60a5fa;font-size:0.72rem'>🔗 Open</a>\"
        line += f\"<div class='cmd-copy' style='flex:1;padding:0.2rem 0.5rem;font-size:0.68rem;position:relative' onclick=\\\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\\\" data-cmd=\\\"{esc_cmd}\\\">📋 {h.escape(cmd[:60])}</div>\"
        line += \"</div>\"
        items.append(line)
    print('\\n'.join(items))
" 2>/dev/null)
            if [[ -n "$explore_items" ]]; then
                actions+="<div class='dropdown'>"
                actions+="<button class='dropdown-toggle' style='background:rgba(129,140,248,0.12);border-color:rgba(129,140,248,0.3);color:#a5b4fc'>🔓 Explore</button>"
                actions+="<div class='dropdown-menu dropdown-menu-wide'>"
                actions+="$explore_items"
                actions+="</div></div>"
            fi
        fi

        actions+="</div>"

        echo "<tr><td>$idx</td><td>$badge</td><td><a href=\"https://$sub\" target=\"_blank\" style=\"color:#60a5fa\"><code>$sub</code></a></td><td class=\"ip-cell\">$ip_html</td><td class=\"ai-infra-cell\" data-host=\"$sub\"><span style=\"color:#64748b\">aguardando IA</span></td><td>$ports_html</td><td class=\"actions-cell\">$actions</td></tr>" >> "${DASHBOARD_DIR}/subdomains.html"
        idx=$((idx + 1))
    done

    # Build list of active subdomains for general fuzz commands
    local active_subs_list=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | cut -d'|' -f1 | sort -u | tr '\n' ' ')

    # Use Python to generate the fuzz card HTML (avoids all shell escaping issues)
    python3 -c "
import html
subs = '${active_subs_list}'.strip()
tools = [
    ('gobuster', 'gobuster dir -u https://\$sub/ -w /usr/share/dirb/wordlists/big.txt -k -t 100 -e --no-error -r -o fuzz-gobuster-\$sub -a Mozilla/5.0 --exclude-length 123456 -x php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log'),
    ('feroxbuster', 'feroxbuster --url https://\$sub/ --methods GET,POST -r -A -w /usr/share/dirb/wordlists/big.txt -o fuzz-feroxbuster-\$sub -x php bkp old txt xml cgi pdf html htm asp aspx pl sql js png jpg jpeg config sh cfm zip log'),
    ('dirsearch', 'dirsearch -u https://\$sub/ --crawl --full-url -t 1 --user-agent Mozilla/5.0 -e php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log -o fuzz-dirsearch-\$sub'),
    ('ffuf', 'ffuf -u https://\$sub/FUZZ -w /usr/share/dirb/wordlists/big.txt -c -t 100 -e .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.zip,.log -o fuzz-ffuf-\$sub.html -of html'),
    ('dirb', 'dirb https://\$sub/ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -a KidMan -X .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.sh,.cfm,.zip,.log -o fuzz-dirb-\$sub'),
]
print('</tbody></table></div>')
print('<div class=\"card\" style=\"border-left:3px solid #fb923c;margin-top:1.5rem\">')
print('<h3>🔥 Fuzz Geral — Executar em TODOS os subdomínios ativos</h3>')
print('<p style=\"color:#94a3b8;font-size:0.85rem;margin-bottom:1rem\">Clique para copiar o comando completo (saída salva em arquivo)</p>')
print('<div style=\"display:flex;flex-wrap:wrap;gap:0.5rem\">')
for name, tool_cmd in tools:
    cmd = f'for sub in {subs}; do echo \"[*] Fuzzing \$sub with {name}...\"; {tool_cmd}; done | tee -a fuzzing-{name}-all-subs.txt'
    escaped = html.escape(cmd, quote=True)
    print(f'<div class=\"cmd-copy fuzz-all-btn\" style=\"display:inline-block;padding:0.5rem 1rem;background:rgba(251,146,60,0.12);border:1px solid rgba(251,146,60,0.3);border-radius:0.5rem;cursor:pointer;font-size:0.8rem;color:#fdba74;position:relative\" onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add(&#39;copied&#39;);setTimeout(()=>this.classList.remove(&#39;copied&#39;),1500)\" data-cmd=\"{escaped}\">📋 {name} ALL</div>')
print('</div></div>')
" >> "${DASHBOARD_DIR}/subdomains.html"

    cat >> "${DASHBOARD_DIR}/subdomains.html" <<'EOFHTML'
</div><script src="assets/ai-data.js"></script><script src="assets/script.js"></script><script>
document.addEventListener('DOMContentLoaded',()=>{const data=window.WBRID_AI_DATA||{},rows=Array.isArray(data.infrastructure)?data.infrastructure:[],byHost={};rows.forEach(item=>{const host=String(item.host||'').toLowerCase();if(host)(byHost[host]||(byHost[host]=[])).push(item)});document.querySelectorAll('.ai-infra-cell').forEach(cell=>{const items=byHost[String(cell.dataset.host||'').toLowerCase()]||[];cell.textContent='';if(!items.length){cell.textContent=data.status==='ready'?'—':'aguardando IA';return}items.slice(0,4).forEach(item=>{const line=document.createElement('div'),provider=document.createElement('strong'),detail=document.createElement('small');provider.textContent=item.provider||'Provedor detectado';detail.textContent=`${item.type||''}${item.ip?' · '+item.ip:''}`;detail.style.display='block';detail.style.color='#64748b';line.append(provider,detail);line.title=item.evidence||'';line.style.marginBottom='.35rem';cell.appendChild(line)})})});
</script></body></html>
EOFHTML
}

# ============================================
# PAGE: BIRD-CRAFTJS
# ============================================

generate_brid_page() {
    local sorted_file="${TEMP_DIR}/craftjs_sorted.txt"
    if [[ -s "$CRAFTJS_FILE" ]]; then
        sort -u "$CRAFTJS_FILE" > "$sorted_file"
    else
        touch "$sorted_file"
    fi
    local count=$(wc -l < "$sorted_file" | tr -d ' ')

    # Use Python to group by titulo+dado, count occurrences, collect source URLs
    python3 -c "
import json, html as h, sys
from collections import defaultdict

groups = defaultdict(lambda: {'count': 0, 'urls': []})
try:
    for line in open('$sorted_file'):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            titulo = d.get('titulo', '')
            dado = d.get('dado', '')
            url = d.get('url', '')
            key = (titulo, dado)
            groups[key]['count'] += 1
            if url and url not in groups[key]['urls']:
                groups[key]['urls'].append(url)
        except: pass
except: pass

# Sort by titulo then dado
sorted_groups = sorted(groups.items(), key=lambda x: (x[0][0].lower(), x[0][1].lower()))

# Write HTML
print('<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">')
print('<title>${REPORT_TITLE}</title><link rel=\"stylesheet\" href=\"assets/style.css\">')
print('<style>')
print('.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:1000;justify-content:center;align-items:center}')
print('.modal-overlay.active{display:flex}')
print('.modal-box{background:#1e293b;border:1px solid rgba(99,102,241,0.3);border-radius:0.75rem;padding:1.5rem;max-width:700px;width:90%;max-height:70vh;overflow-y:auto}')
print('.modal-box h3{color:#a5b4fc;margin-bottom:1rem}')
print('.modal-box a{display:block;color:#60a5fa;font-size:0.8rem;padding:0.3rem 0;word-break:break-all}')
print('.modal-box a:hover{color:#93c5fd}')
print('.modal-close{float:right;background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer}')
print('.modal-close:hover{color:#fff}')
print('.count-badge{display:inline-block;min-width:24px;text-align:center;padding:0.15rem 0.4rem;border-radius:0.3rem;font-size:0.75rem;font-weight:bold}')
print('.count-1{background:rgba(99,102,241,0.15);color:#a5b4fc}')
print('.count-multi{background:rgba(251,146,60,0.2);color:#fdba74}')
print('.src-btn{padding:0.2rem 0.6rem;border-radius:0.3rem;border:1px solid rgba(96,165,250,0.3);background:rgba(96,165,250,0.08);color:#60a5fa;font-size:0.72rem;cursor:pointer}')
print('.src-btn:hover{background:rgba(96,165,250,0.2)}')
print('.craft-wrap{overflow-x:hidden}')
print('.craft-table{width:100%;table-layout:fixed}')
print('.craft-table th:nth-child(1){width:58px}.craft-table th:nth-child(2){width:18%}.craft-table th:nth-child(4){width:76px}.craft-table th:nth-child(5){width:120px}')
print('.craft-data,.craft-data code,.modal-data{display:block;max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}')
print('.craft-table td{vertical-align:top}')
print('</style>')
print('</head><body>')
" > "${DASHBOARD_DIR}/brid-craftjs.html"

    generate_nav "brid" >> "${DASHBOARD_DIR}/brid-craftjs.html"

    python3 -c "
import json, html as h
from collections import defaultdict

groups = defaultdict(lambda: {'count': 0, 'urls': []})
try:
    for line in open('$sorted_file'):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            titulo = d.get('titulo', '')
            dado = d.get('dado', '')
            url = d.get('url', '')
            key = (titulo, dado)
            groups[key]['count'] += 1
            if url and url not in groups[key]['urls']:
                groups[key]['urls'].append(url)
        except: pass
except: pass

sorted_groups = sorted(groups.items(), key=lambda x: (x[0][0].lower(), x[0][1].lower()))
unique_count = len(sorted_groups)
total_count = sum(v['count'] for v in groups.values())

print(f'<div class=\"container\">')
print(f'<div class=\"card\"><h2>Bird-CraftJS</h2>')
print(f'<p>Total: <strong>{total_count}</strong> achados • <strong>{unique_count}</strong> únicos (agrupados por conteúdo)</p></div>')
print('<div class=\"filter-bar\"><input type=\"text\" id=\"searchInput\" placeholder=\"🔍 Buscar...\"><button class=\"export-btn\" onclick=\"exportCSV()\">📄 CSV</button><button class=\"export-btn\" onclick=\"exportJSON()\">📋 JSON</button></div>')
print('<div class=\"table-container craft-wrap\"><table class=\"craft-table\"><thead><tr><th>#</th><th>Título</th><th>Dado</th><th>Qtd</th><th>Fontes</th></tr></thead><tbody>')

modals = []
for idx, ((titulo, dado), info) in enumerate(sorted_groups, 1):
    cnt = info['count']
    urls = info['urls']
    t_esc = h.escape(titulo)
    d_esc = h.escape(dado)
    cnt_class = 'count-1' if cnt == 1 else 'count-multi'
    modal_id = f'modal-{idx}'

    print(f'<tr><td>{idx}</td><td><strong>{t_esc}</strong></td><td class=\"craft-data\"><code style=\"color:#fca5a5\">{d_esc}</code></td>')
    print(f'<td><span class=\"count-badge {cnt_class}\">{cnt}×</span></td>')
    print(f'<td><button class=\"src-btn\" onclick=\"document.getElementById(\\'{modal_id}\\').classList.add(\\'active\\')\">')
    print(f'🔗 {len(urls)} fonte{\"s\" if len(urls)!=1 else \"\"}</button></td></tr>')

    # Collect modal HTML to render OUTSIDE the table
    urls_html = ''.join([f'<a href=\"{h.escape(u)}\" target=\"_blank\">{h.escape(u)}</a>' for u in urls])
    modals.append(f'<div id=\"{modal_id}\" class=\"modal-overlay\" onclick=\"if(event.target===this)this.classList.remove(\\'active\\')\">'
        f'<div class=\"modal-box\">'
        f'<button class=\"modal-close\" onclick=\"this.closest(\\'.modal-overlay\\').classList.remove(\\'active\\')\">&times;</button>'
        f'<h3>🔗 Fontes: {t_esc}</h3>'
        f'<code class=\"modal-data\" style=\"color:#fca5a5;font-size:0.85rem\">{d_esc}</code><hr style=\"border-color:#334155;margin:0.8rem 0\">'
        f'{urls_html}'
        f'</div></div>')

print('</tbody></table></div>')

# Print modals OUTSIDE the table so display:none parent doesn't block them
for m in modals:
    print(m)

print('</div>')

# Modal CSS is in head already, no extra JS needed — modals use onclick inline
print('<script src=\"assets/script.js\"></script></body></html>')
" >> "${DASHBOARD_DIR}/brid-craftjs.html"
}

# ============================================
# PAGE: URLs (deduplicated + sorted)
# ============================================

generate_urls_page() {
    # Deduplicate and sort URLs
    local sorted_urls="${TEMP_DIR}/urls_sorted.txt"
    sort -u "$URLS_FILE" > "$sorted_urls"
    local count=$(wc -l < "$sorted_urls" | tr -d ' ')
    cat > "${DASHBOARD_DIR}/urls.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${REPORT_TITLE}</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "urls")
<div class="container">
    <div class="card"><h2>🔗 URLs Coletadas <span class="llm-badge">📊 Auto</span></h2><p>Total: <strong id="visibleCount">$count</strong> URLs únicas em escopo</p></div>
    <div class="filter-bar"><input type="text" id="searchInput" placeholder="🔍 Buscar URLs..."><button class="export-btn" onclick="exportCSV()">📄 CSV</button><button class="export-btn" onclick="exportJSON()">📋 JSON</button></div>
    <div class="table-container"><table><thead><tr><th>#</th><th>URL</th></tr></thead><tbody>
EOFHTML
    local idx=1
    while IFS= read -r url; do
        local safe=$(echo "$url" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g')
        echo "<tr><td>$idx</td><td><a href=\"$url\" target=\"_blank\" style=\"color:#60a5fa;word-break:break-all\">$safe</a></td></tr>" >> "${DASHBOARD_DIR}/urls.html"
        idx=$((idx + 1))
    done < "$sorted_urls"
    echo "</tbody></table></div></div><script src=\"assets/script.js\"></script></body></html>" >> "${DASHBOARD_DIR}/urls.html"
}

# ============================================
# PAGE: Tree (folder structure from URLs)
# ============================================

generate_tree_page() {
    local sorted_urls="${TEMP_DIR}/urls_sorted.txt"
    [[ ! -f "$sorted_urls" ]] && sort -u "$URLS_FILE" > "$sorted_urls"

    # Build tree JSON from URLs using Python
    local tree_json
    tree_json=$(python3 -c "
import json,sys
from urllib.parse import urlparse

tree={}
for line in sys.stdin:
    url=line.strip()
    if not url: continue
    try:
        p=urlparse(url)
        host=p.netloc or p.path.split('/')[0]
        path=p.path.strip('/')
        parts=[host]+[x for x in path.split('/') if x]
        node=tree
        for part in parts:
            if part not in node:
                node[part]={}
            node=node[part]
        if p.query:
            q='?'+p.query
            if q not in node: node[q]={}
    except:
        pass

def sort_tree(t):
    return {k:sort_tree(v) for k,v in sorted(t.items(), key=lambda x:(0 if x[1] else 1, x[0].lower()))}

print(json.dumps(sort_tree(tree)))
" < "$sorted_urls" 2>/dev/null)
    [[ -z "$tree_json" ]] && tree_json='{}'

    local total_dirs=$(echo "$tree_json" | python3 -c "import json,sys;d=json.load(sys.stdin);c=[0];exec('def count(n):\n    for k,v in n.items():\n        if v: c[0]+=1; count(v)');count(d);print(c[0])" 2>/dev/null || echo 0)
    local total_files=$(echo "$tree_json" | python3 -c "import json,sys;d=json.load(sys.stdin);c=[0];exec('def count(n):\n    for k,v in n.items():\n        if not v: c[0]+=1\n        else: count(v)');count(d);print(c[0])" 2>/dev/null || echo 0)

    cat > "${DASHBOARD_DIR}/tree.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${REPORT_TITLE}</title><link rel="stylesheet" href="assets/style.css">
<style>
.tree-container{font-family:'JetBrains Mono',monospace;font-size:0.82rem;line-height:1.8}
.tree-node{padding-left:1.2rem;border-left:1px solid rgba(99,102,241,0.15)}
.tree-toggle{cursor:pointer;user-select:none;padding:0.15rem 0;display:block;color:#93c5fd;transition:color 0.2s}
.tree-toggle:hover{color:#60a5fa}
.tree-toggle::before{content:'▶ ';font-size:0.65rem;color:#6366f1;display:inline-block;transition:transform 0.2s;margin-right:0.3rem}
.tree-toggle.open::before{transform:rotate(90deg)}
.tree-file{padding:0.15rem 0;padding-left:1.2rem;color:#94a3b8;display:block}
.tree-file::before{content:'📄 ';font-size:0.7rem}
.tree-file.ext-js::before,.tree-file.ext-json::before{content:'🟡 '}
.tree-file.ext-php::before,.tree-file.ext-py::before{content:'🟣 '}
.tree-file.ext-html::before,.tree-file.ext-htm::before{content:'🟠 '}
.tree-file.ext-css::before{content:'🟢 '}
.tree-file.ext-xml::before,.tree-file.ext-config::before{content:'⚙️ '}
.tree-file.ext-pdf::before,.tree-file.ext-doc::before{content:'📝 '}
.tree-file.ext-zip::before,.tree-file.ext-gz::before{content:'📦 '}
.tree-file.ext-png::before,.tree-file.ext-jpg::before,.tree-file.ext-jpeg::before{content:'🖼️ '}
.tree-dir::before{content:'📁 '}
.tree-host{font-size:0.95rem;font-weight:600;color:#a5b4fc;padding:0.5rem 0}
.tree-host::before{content:'🌐 '}
.tree-stats{display:flex;gap:1.5rem;margin-bottom:1rem;color:#64748b;font-size:0.8rem}
.tree-actions{display:flex;gap:0.5rem;margin-bottom:1rem}
.tree-btn{padding:0.4rem 0.8rem;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);border-radius:0.4rem;color:#a5b4fc;cursor:pointer;font-size:0.75rem;font-family:'Inter',system-ui,sans-serif;transition:all 0.2s}
.tree-btn:hover{background:rgba(99,102,241,0.25)}
.tree-link{color:#6366f1;text-decoration:none;font-size:0.7rem;opacity:0.5;transition:all 0.2s;padding:0.1rem 0.3rem;border-radius:0.2rem}
.tree-link:hover{opacity:1;background:rgba(99,102,241,0.15);color:#818cf8}
a.tree-file{text-decoration:none;cursor:pointer}
a.tree-file:hover{color:#60a5fa;text-decoration:underline}
</style></head><body>
$(generate_nav "tree")
<div class="container">
    <div class="card"><h2>🌳 Estrutura de Diretórios <span class="llm-badge">📊 Auto</span></h2>
    <div class="tree-stats"><span>📁 $total_dirs diretórios</span><span>📄 $total_files arquivos</span></div>
    </div>
    <div class="filter-bar"><input type="text" id="treeSearch" placeholder="🔍 Buscar na árvore..."></div>
    <div class="tree-actions">
        <button class="tree-btn" onclick="expandAll()">📂 Expandir Tudo</button>
        <button class="tree-btn" onclick="collapseAll()">📁 Recolher Tudo</button>
    </div>
    <div class="card"><div class="tree-container" id="treeRoot"></div></div>
</div>
<script>
const TREE_DATA = $tree_json;

function buildTree(data, container, depth, parentPath) {
    const sorted = Object.entries(data).sort((a,b) => {
        const aDir = Object.keys(a[1]).length > 0;
        const bDir = Object.keys(b[1]).length > 0;
        if (aDir !== bDir) return aDir ? -1 : 1;
        return a[0].toLowerCase().localeCompare(b[0].toLowerCase());
    });
    sorted.forEach(([name, children]) => {
        const isDir = Object.keys(children).length > 0;
        const currentPath = parentPath ? parentPath + '/' + name : name;
        if (isDir) {
            const wrapper = document.createElement('div');
            wrapper.style.display = 'flex';
            wrapper.style.alignItems = 'center';
            wrapper.style.gap = '0.3rem';
            const toggle = document.createElement('span');
            toggle.className = depth === 0 ? 'tree-toggle tree-host' : 'tree-toggle tree-dir';
            toggle.textContent = name;
            toggle.onclick = function(e) {
                e.stopPropagation();
                this.parentElement.nextElementSibling.style.display = 
                    this.parentElement.nextElementSibling.style.display === 'none' ? 'block' : 'none';
                this.classList.toggle('open');
            };
            wrapper.appendChild(toggle);
            // Add clickable link icon for directories
            const dirLink = document.createElement('a');
            dirLink.className = 'tree-link';
            dirLink.textContent = '\u2197';
            dirLink.title = 'Abrir: ' + currentPath + '/';
            if (depth === 0) {
                dirLink.href = 'https://' + name + '/';
            } else {
                // Reconstruct URL from path: first segment is host
                const parts = currentPath.split('/');
                dirLink.href = 'https://' + parts.join('/') + '/';
            }
            dirLink.target = '_blank';
            dirLink.onclick = function(e) { e.stopPropagation(); };
            wrapper.appendChild(dirLink);
            container.appendChild(wrapper);
            const node = document.createElement('div');
            node.className = 'tree-node';
            node.style.display = depth < 1 ? 'block' : 'none';
            buildTree(children, node, depth + 1, currentPath);
            container.appendChild(node);
        } else {
            const fileLink = document.createElement('a');
            const ext = name.split('.').pop().toLowerCase();
            fileLink.className = 'tree-file ext-' + ext;
            fileLink.textContent = name;
            // Build full URL
            const parts = currentPath.split('/');
            fileLink.href = 'https://' + parts.join('/');
            fileLink.target = '_blank';
            fileLink.title = 'Abrir: https://' + parts.join('/');
            container.appendChild(fileLink);
        }
    });
}

function expandAll() {
    document.querySelectorAll('.tree-node').forEach(n => n.style.display = 'block');
    document.querySelectorAll('.tree-toggle').forEach(t => t.classList.add('open'));
}
function collapseAll() {
    document.querySelectorAll('.tree-node').forEach((n,i) => { if(i>0) n.style.display='none'; });
    document.querySelectorAll('.tree-toggle').forEach((t,i) => { if(i>0) t.classList.remove('open'); });
}

document.getElementById('treeSearch').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    if (!q) { collapseAll(); document.querySelectorAll('.tree-node')[0].style.display='block'; return; }
    document.querySelectorAll('.tree-toggle,.tree-file').forEach(el => {
        const match = el.textContent.toLowerCase().includes(q);
        const parent = el.closest('div[style]') || el;
        parent.style.display = match ? '' : 'none';
        if (match) {
            let p = el.parentElement;
            while (p && p.id !== 'treeRoot') {
                if (p.classList.contains('tree-node')) p.style.display = 'block';
                const prev = p.previousElementSibling;
                if (prev) {
                    const tog = prev.querySelector ? prev.querySelector('.tree-toggle') : null;
                    if (tog) { tog.classList.add('open'); tog.parentElement.style.display = ''; }
                    else if (prev.classList && prev.classList.contains('tree-toggle')) {
                        prev.classList.add('open'); prev.style.display = '';
                    }
                }
                p = p.parentElement;
            }
        }
    });
});

buildTree(TREE_DATA, document.getElementById('treeRoot'), 0, '');
// Auto-expand first level
document.querySelectorAll('#treeRoot > div > .tree-toggle').forEach(t => t.classList.add('open'));
</script></body></html>
EOFHTML
}

# ============================================
# PAGE: FINAL FINDINGS
# ============================================

generate_final_findings_page() {
    cat > "${DASHBOARD_DIR}/final-findings.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${REPORT_TITLE}</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "final")
<main class="container"><section class="card hero-card"><span class="eyebrow">correlação dinâmica</span><h2>Final Findings</h2><p>Achados consolidados por causa raiz; URLs repetidas aparecem somente como ocorrências.</p></section>
<div class="filter-bar"><input id="findingSearch" type="search" placeholder="Buscar achado, categoria ou alvo..."><select id="findingSeverity"><option value="">Todas as severidades</option><option value="critical">Crítico</option><option value="high">Alto</option><option value="medium">Médio</option><option value="low">Baixo</option></select></div>
<section id="finalFindingList">
EOFHTML
    FINAL_FINDINGS_FILE="$FINAL_FINDINGS_FILE" python3 <<'PYEOF' >> "${DASHBOARD_DIR}/final-findings.html"
import html, json, os

groups = {}
path = os.environ["FINAL_FINDINGS_FILE"]
try:
    lines = open(path, encoding="utf-8", errors="replace")
except OSError:
    lines = []
for raw in lines:
    try:
        item = json.loads(raw)
    except ValueError:
        continue
    key = item.get("merge_key") or "|".join(str(item.get(name, "")) for name in ("id", "target", "title"))
    current = groups.setdefault(key, dict(item, urls=[], source_files=[], occurrences=0))
    current["occurrences"] += int(item.get("occurrences") or 1)
    for url in item.get("urls") or []:
        if url not in current["urls"]:
            current["urls"].append(url)
    source = item.get("_source_file")
    if source and source not in current["source_files"]:
        current["source_files"].append(source)

rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
items = sorted(groups.values(), key=lambda row: (rank.get(row.get("severity"), 9), row.get("category", ""), row.get("title", "")))
if not items:
    print('<div class="empty-state">Nenhum achado consolidado disponível para o escopo atual.</div>')
for index, item in enumerate(items, 1):
    severity = item.get("severity", "info")
    title = html.escape(str(item.get("title", "Achado")))
    category = html.escape(str(item.get("category", "Outro")))
    target = html.escape(str(item.get("target", "")))
    confidence = html.escape(str(item.get("confidence", "")))
    description = html.escape(str(item.get("description", "")))
    impact = html.escape(str(item.get("impact", "")))
    recommendation = html.escape(str(item.get("recommendation", "")))
    evidence = html.escape(str(item.get("evidence", "")))
    urls = item.get("urls", [])
    occurrences = max(item.get("occurrences", 0), len(urls), 1)
    search = html.escape(f"{title} {category} {target}".lower(), quote=True)
    print(f'<article class="card finding-card severity-{severity}" data-severity="{severity}" data-search="{search}">')
    print(f'<span class="section-number">#{index:03d} · {html.escape(str(item.get("id", "FINDING")))}</span><h3>{title}</h3>')
    print(f'<div class="finding-meta"><span>{category}</span><span>{severity.upper()}</span><span>confiança {confidence}</span><span>{occurrences} ocorrência(s)</span><span>{target}</span></div>')
    if description: print(f'<p>{description}</p>')
    if impact: print(f'<details><summary>Impacto</summary><p>{impact}</p></details>')
    if recommendation: print(f'<details><summary>Recomendação</summary><p>{recommendation}</p></details>')
    if evidence: print(f'<details><summary>Evidência representativa</summary><pre class="evidence-block">{evidence}</pre></details>')
    if urls:
        print(f'<details><summary>URLs afetadas — exibindo {min(5, len(urls))} de {len(urls)}</summary><div class="evidence-block">')
        for url in urls[:5]:
            safe = html.escape(str(url))
            print(f'<a href="{safe}" target="_blank" rel="noreferrer">{safe}</a><br>')
        print('</div></details>')
    print('</article>')
PYEOF
    cat >> "${DASHBOARD_DIR}/final-findings.html" <<'EOFHTML'
</section></main><script src="assets/script.js"></script><script>
const fs=document.getElementById('findingSearch'),fv=document.getElementById('findingSeverity'),cards=[...document.querySelectorAll('.finding-card')];
function filterFindings(){const q=(fs.value||'').toLowerCase(),s=fv.value;cards.forEach(c=>c.hidden=!(c.dataset.search.includes(q)&&(!s||c.dataset.severity===s)))}
fs.addEventListener('input',filterFindings);fv.addEventListener('change',filterFindings);
</script></body></html>
EOFHTML
}

# ============================================
# PAGE: AI FINDINGS
# ============================================

generate_ai_assets() {
    if [[ "$AI_ENABLED" =~ ^(1|s|S|y|Y)$ ]]; then
        echo 'window.WBRID_AI_STATUS={status:"pending"};' > "${ASSETS_DIR}/ai-status.js"
        echo 'window.WBRID_AI_DATA={status:"pending",findings:[],api_endpoints:[],infrastructure:[],technologies:[],coverage:{}};' > "${ASSETS_DIR}/ai-data.js"
    else
        echo 'window.WBRID_AI_STATUS={status:"disabled"};' > "${ASSETS_DIR}/ai-status.js"
        echo 'window.WBRID_AI_DATA={status:"disabled",findings:[],api_endpoints:[],infrastructure:[],technologies:[],coverage:{}};' > "${ASSETS_DIR}/ai-data.js"
    fi
    cat > "${DASHBOARD_DIR}/ai-findings.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${REPORT_TITLE}</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "ai")
<main class="container"><section class="card hero-card"><span class="eyebrow">análise complementar</span><h2>IA Findings</h2><p>Correlação dos outputs, JavaScript em escopo e validações de conteúdo.</p><div id="aiCoverage" class="scope-meta"></div></section><section id="aiInfraSection" class="card" hidden><span class="eyebrow">infraestrutura detectada</span><h3>WAF, CDN e Cloud</h3><div class="filter-bar"><input id="aiInfraSearch" type="search" placeholder="Buscar host, provedor ou tipo..."><span id="aiInfraCount" class="scope-pill"></span></div><div class="table-container"><table><thead><tr><th>Host</th><th>Provedor</th><th>Tipo</th><th>Evidência</th></tr></thead><tbody id="aiInfraBody"></tbody></table></div><div class="filter-bar"><button id="aiInfraPrev" class="export-btn" type="button">Anterior</button><span id="aiInfraPage" class="scope-pill"></span><button id="aiInfraNext" class="export-btn" type="button">Próxima</button></div></section><section id="aiTechSection" class="card" hidden><span class="eyebrow">fingerprint validado</span><h3>Tecnologias e versões</h3><div class="filter-bar"><input id="aiTechSearch" type="search" placeholder="Buscar host, tecnologia ou versão..."><span id="aiTechCount" class="scope-pill"></span></div><div class="table-container"><table><thead><tr><th>Host</th><th>Tecnologia</th><th>Versão</th><th>Encontrado em</th></tr></thead><tbody id="aiTechBody"></tbody></table></div></section><section id="aiApiSection" class="card" hidden><span class="eyebrow">inventário correlacionado</span><h3>Endpoints de API</h3><div class="filter-bar"><input id="aiApiSearch" type="search" placeholder="Buscar método, endpoint ou fonte..."><span id="aiApiCount" class="scope-pill"></span></div><div class="table-container"><table><thead><tr><th>Método</th><th>Endpoint completo</th><th>Encontrado em</th></tr></thead><tbody id="aiApiBody"></tbody></table></div><div class="filter-bar"><button id="aiApiPrev" class="export-btn" type="button">Anterior</button><span id="aiApiPage" class="scope-pill"></span><button id="aiApiNext" class="export-btn" type="button">Próxima</button></div></section><div class="filter-bar"><input id="aiSearch" type="search" placeholder="Buscar achados da IA..."><select id="aiSeverity"><option value="">Todas as severidades</option><option value="critical">Crítico</option><option value="high">Alto</option><option value="medium">Médio</option><option value="low">Baixo</option><option value="info">Informativo</option></select></div><section id="aiFindingList"><div class="empty-state">A análise ainda está em processamento. Atualize a página em alguns instantes.</div></section></main>
EOFHTML
    cat >> "${DASHBOARD_DIR}/ai-findings.html" <<'EOFHTML'
<script src="assets/ai-data.js"></script><script src="assets/script.js"></script><script>
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sourceDetails=values=>{const sources=[...new Set(Array.isArray(values)?values:[])];if(!sources.length)return '<span style="color:#64748b">—</span>';return `<details><summary>${sources.length} fonte${sources.length===1?'':'s'}</summary><div class="evidence-block">${sources.map(source=>{const safe=esc(source);return /^https?:\/\//i.test(source)?`<a href="${safe}" target="_blank" rel="noreferrer">${safe}</a>`:`<code>${safe}</code>`}).join('<br>')}</div></details>`};
const data=window.WBRID_AI_DATA||{},list=document.getElementById('aiFindingList'),coverage=document.getElementById('aiCoverage');
if(data.status==='ready'){
  const c=data.coverage||{};coverage.innerHTML=`<span class="scope-pill">${Number(c.files_processed||0)} arquivos</span><span class="scope-pill">${Number(c.bytes_processed||0).toLocaleString()} bytes</span><span class="scope-pill">${Number(c.js_analyzed||0)} JS em escopo</span><span class="scope-pill">${Number(c.api_endpoints_discovered||0).toLocaleString()} endpoints de API</span><span class="scope-pill">${Number(c.llm_calls_completed||0)}/${Number(c.llm_calls_planned||0)} lotes IA</span><span class="scope-pill">${Number(c.sitemaps_processed||0)} sitemaps</span>${c.analysis_complete===false?'<span class="scope-pill">cobertura parcial</span>':''}`;
  const infra=Array.isArray(data.infrastructure)?data.infrastructure:[],infraSection=document.getElementById('aiInfraSection'),infraBody=document.getElementById('aiInfraBody'),infraSearch=document.getElementById('aiInfraSearch'),infraCount=document.getElementById('aiInfraCount'),infraPage=document.getElementById('aiInfraPage');let infraCurrent=1;const infraPageSize=50;
  function renderInfra(){const q=(infraSearch.value||'').toLowerCase(),filtered=infra.filter(item=>`${item.host||''} ${item.ip||''} ${item.provider||''} ${item.type||''} ${item.evidence||''}`.toLowerCase().includes(q)),pages=Math.max(1,Math.ceil(filtered.length/infraPageSize));infraCurrent=Math.min(infraCurrent,pages);const start=(infraCurrent-1)*infraPageSize;infraBody.innerHTML=filtered.slice(start,start+infraPageSize).map(item=>`<tr><td><code>${esc(item.host)}</code>${item.ip?`<br><small>${esc(item.ip)}</small>`:''}</td><td>${esc(item.provider)}</td><td>${esc(item.type)}</td><td>${esc(item.evidence)}</td></tr>`).join('')||'<tr><td colspan="4">Nenhuma infraestrutura corresponde ao filtro.</td></tr>';infraCount.textContent=`${filtered.length.toLocaleString()} sinal(is)`;infraPage.textContent=`Página ${infraCurrent} de ${pages}`;document.getElementById('aiInfraPrev').disabled=infraCurrent<=1;document.getElementById('aiInfraNext').disabled=infraCurrent>=pages}
  if(infra.length){infraSection.hidden=false;renderInfra();infraSearch.addEventListener('input',()=>{infraCurrent=1;renderInfra()});document.getElementById('aiInfraPrev').addEventListener('click',()=>{infraCurrent--;renderInfra()});document.getElementById('aiInfraNext').addEventListener('click',()=>{infraCurrent++;renderInfra()})}
  const tech=Array.isArray(data.technologies)?data.technologies:[],techSection=document.getElementById('aiTechSection'),techBody=document.getElementById('aiTechBody'),techSearch=document.getElementById('aiTechSearch'),techCount=document.getElementById('aiTechCount');
  function renderTech(){const q=(techSearch.value||'').toLowerCase(),filtered=tech.filter(item=>`${item.host||''} ${item.name||''} ${item.version||''} ${(item.sources||[]).join(' ')}`.toLowerCase().includes(q));techBody.innerHTML=filtered.slice(0,200).map(item=>`<tr><td><code>${esc(item.host)}</code></td><td>${esc(item.name)}</td><td>${esc(item.version||'não exposta')}</td><td>${sourceDetails(item.sources)}</td></tr>`).join('')||'<tr><td colspan="4">Nenhuma tecnologia corresponde ao filtro.</td></tr>';techCount.textContent=`${filtered.length.toLocaleString()} tecnologia(s)${filtered.length>200?' · primeiras 200 exibidas':''}`}
  if(tech.length){techSection.hidden=false;renderTech();techSearch.addEventListener('input',renderTech)}
  const endpoints=Array.isArray(data.api_endpoints)?data.api_endpoints:[],apiSection=document.getElementById('aiApiSection'),apiBody=document.getElementById('aiApiBody'),apiSearch=document.getElementById('aiApiSearch'),apiCount=document.getElementById('aiApiCount'),apiPage=document.getElementById('aiApiPage');let apiCurrent=1;const apiPageSize=50;
  function renderAPI(){const q=(apiSearch.value||'').toLowerCase(),filtered=endpoints.filter(item=>`${item.method||''} ${item.url||''} ${(item.sources||[]).join(' ')}`.toLowerCase().includes(q)),pages=Math.max(1,Math.ceil(filtered.length/apiPageSize));apiCurrent=Math.min(apiCurrent,pages);const start=(apiCurrent-1)*apiPageSize;apiBody.innerHTML=filtered.slice(start,start+apiPageSize).map(item=>`<tr><td><code>${esc(item.method||'UNKNOWN')}</code></td><td style="overflow-wrap:anywhere"><a class="api-endpoint-link" href="${esc(item.url)}" target="_blank" rel="noreferrer">${esc(item.url)}</a></td><td>${sourceDetails(item.sources)}</td></tr>`).join('')||'<tr><td colspan="3">Nenhum endpoint corresponde ao filtro.</td></tr>';apiCount.textContent=`${filtered.length.toLocaleString()} endpoint(s)`;apiPage.textContent=`Página ${apiCurrent} de ${pages}`;document.getElementById('aiApiPrev').disabled=apiCurrent<=1;document.getElementById('aiApiNext').disabled=apiCurrent>=pages}
  if(endpoints.length){apiSection.hidden=false;renderAPI();apiSearch.addEventListener('input',()=>{apiCurrent=1;renderAPI()});document.getElementById('aiApiPrev').addEventListener('click',()=>{apiCurrent--;renderAPI()});document.getElementById('aiApiNext').addEventListener('click',()=>{apiCurrent++;renderAPI()})}
  const findings=Array.isArray(data.findings)?data.findings:[];
  list.innerHTML=findings.length?'':'<div class="empty-state">A IA não produziu achados adicionais confirmáveis.</div>';
  findings.forEach((f,i)=>{const urls=(f.urls||[]).slice(0,5),sources=f.sources||[],article=document.createElement('article');article.className=`card finding-card severity-${esc(f.severity||'info')}`;article.dataset.severity=f.severity||'info';article.dataset.search=`${f.title||''} ${f.category||''} ${f.target||''}`.toLowerCase();article.innerHTML=`<span class="section-number">#${String(i+1).padStart(3,'0')} · IA</span><h3>${esc(f.title||'Achado complementar')}</h3><div class="finding-meta"><span>${esc(f.category||'Correlação')}</span><span>${esc((f.severity||'info').toUpperCase())}</span><span>confiança ${esc(f.confidence||'média')}</span><span>${esc(f.target||'')}</span></div><p>${esc(f.description||'')}</p>${f.evidence?`<details><summary>Evidência</summary><pre class="evidence-block">${esc(f.evidence)}</pre></details>`:''}${f.recommendation?`<details><summary>Recomendação</summary><p>${esc(f.recommendation)}</p></details>`:''}${sources.length?sourceDetails(sources):''}${urls.length?`<details><summary>URLs representativas</summary><div class="evidence-block">${urls.map(u=>`<a href="${esc(u)}" target="_blank" rel="noreferrer">${esc(u)}</a>`).join('<br>')}</div></details>`:''}`;list.appendChild(article)});
} else if(data.status==='error'){list.innerHTML=`<div class="empty-state">A análise falhou: ${esc(data.error||'erro não informado')}</div>`}
const s=document.getElementById('aiSearch'),v=document.getElementById('aiSeverity');function filterAI(){const q=(s.value||'').toLowerCase();document.querySelectorAll('#aiFindingList .finding-card').forEach(c=>c.hidden=!(c.dataset.search.includes(q)&&(!v.value||c.dataset.severity===v.value)))}s.addEventListener('input',filterAI);v.addEventListener('change',filterAI);
</script></body></html>
EOFHTML
}

# ============================================
# MAIN
# ============================================

main() {
    echo "================================================"
    echo "  Bird Tool Web - Dashboard Generator v3"
    echo "  Análise: Baseada em regras (sem LLM)"
    echo "  Shodan: $([ -n "$SHODAN_API_KEY" ] && echo "✅ InternetDB + API paga" || echo "✅ InternetDB (use SHODAN_API_KEY para fallback)")"
    echo "================================================"
    echo ""

    mkdir -p "$DASHBOARD_DIR" "$ASSETS_DIR"

    if [[ ! -d "$OUT_DIR" ]]; then
        log_error "Diretório OUT-WEB-BIRD não encontrado"
        exit 1
    fi

    # 1. Scope
    build_scope

    # 2. Process data
    process_all_data

    # 3. DNS validation
    validate_subdomains

    # 4. Shodan enrichment
    enrich_with_shodan

    # 5. Generate pages
    log_info "Gerando páginas HTML..."
    generate_css
    generate_js
    generate_ai_assets
    generate_index
    generate_subdomains_page
    generate_brid_page
    generate_urls_page
    generate_tree_page
    generate_dns_page
    generate_final_findings_page
    cp "${DASHBOARD_DIR}/index.html" "${DASHBOARD_DIR}/relatorio.html"

    # Clean up removed pages
    rm -f "${DASHBOARD_DIR}/all-subdomains.html"
    rm -f "${DASHBOARD_DIR}/valid-subdomains.html"
    rm -f "${DASHBOARD_DIR}/fierce.html"
    rm -f "${DASHBOARD_DIR}/repos.html"

    log_success "Dashboard gerado em: ${DASHBOARD_DIR}/"
    log_info "Páginas: index.html, relatorio.html, subdomains.html, brid-craftjs.html, final-findings.html, ai-findings.html, urls.html, tree.html, dns.html"
}

# ============================================
# PAGE: DNS (dnsrecon + dnsenum tree + SPF)
# ============================================

generate_dns_page() {
    python3 << 'PYEOF'
import os, json, csv, re, glob
import html as h
from collections import defaultdict
from io import StringIO

OUT_DIR = os.environ.get("OUT_DIR", "OUT-WEB-BIRD")
DASHBOARD_DIR = os.environ.get("DASHBOARD_DIR", "dashboard")
PRIMARY_DOMAIN = os.environ.get("PRIMARY_DOMAIN", "ESCOPO")

# --- Parse dnsrecon CSV ---
dns_records = []  # list of dicts {domain, type, name, address, target, port, string}
for f in glob.glob(os.path.join(OUT_DIR, "*", "*-dnsrecon")):
    domain = os.path.basename(os.path.dirname(f))
    try:
        with open(f) as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                row['_source'] = 'dnsrecon'
                row['_domain'] = domain
                dns_records.append(row)
    except:
        pass

# --- Parse dnsenum text ---
for f in glob.glob(os.path.join(OUT_DIR, "*", "*-dnsenum")):
    domain = os.path.basename(os.path.dirname(f))
    try:
        with open(f) as fh:
            current_section = ""
            for line in fh:
                line = line.strip()
                if not line or line.startswith("dnsenum") or line.startswith("-----"):
                    continue
                if line.endswith(":") and not line.startswith(" "):
                    current_section = line.rstrip("_: ").strip()
                    continue
                # Parse DNS record lines
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "IN":
                    name = parts[0].rstrip(".")
                    rtype = parts[3]
                    value = parts[4].rstrip(".") if len(parts) > 4 else ""
                    dns_records.append({
                        'Domain': domain,
                        'Type': rtype,
                        'Name': name,
                        'Address': value if rtype in ('A','AAAA') else '',
                        'Target': value if rtype not in ('A','AAAA') else '',
                        'Port': '',
                        'String': '',
                        '_source': 'dnsenum',
                        '_domain': domain
                    })
    except:
        pass

# --- Group by domain then by type ---
by_domain = defaultdict(lambda: defaultdict(list))
for r in dns_records:
    dom = r.get('_domain', r.get('Domain', '?'))
    rtype = r.get('Type', '?')
    by_domain[dom][rtype].append(r)

# --- SPF/DMARC analysis ---
spf_findings = []
dmarc_findings = []
for r in dns_records:
    rtype = r.get('Type', '')
    val = r.get('String', '') or r.get('Target', '') or r.get('Address', '')
    name = r.get('Name', '')
    dom = r.get('_domain', '')
    if rtype == 'TXT' and 'v=spf1' in val.lower():
        # Determine SPF policy
        if '-all' in val:
            policy = '-all (Hard Fail)'
            severity = 'good'
            color = '#4ade80'
            icon = '✅'
        elif '~all' in val:
            policy = '~all (Soft Fail)'
            severity = 'warn'
            color = '#fbbf24'
            icon = '⚠️'
        elif '?all' in val:
            policy = '?all (Neutral)'
            severity = 'danger'
            color = '#f87171'
            icon = '🔴'
        elif '+all' in val:
            policy = '+all (Pass All — DANGEROUS!)'
            severity = 'critical'
            color = '#ef4444'
            icon = '🚨'
        else:
            policy = 'No qualifier found'
            severity = 'warn'
            color = '#fbbf24'
            icon = '❓'
        spf_findings.append({'domain': dom, 'name': name, 'value': val, 'policy': policy, 'severity': severity, 'color': color, 'icon': icon})
    if rtype == 'TXT' and 'v=dmarc' in val.lower():
        dmarc_findings.append({'domain': dom, 'name': name, 'value': val})

# --- Generate HTML ---
out = open(os.path.join(DASHBOARD_DIR, "dns.html"), "w")
out.write('<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">\n')
out.write(f'<title>W-BRID - {h.escape(PRIMARY_DOMAIN)}</title><link rel="stylesheet" href="assets/style.css">\n')
out.write('<style>\n')
out.write('.dns-tree{margin:0.5rem 0}\n')
out.write('.dns-type-header{display:flex;align-items:center;gap:0.5rem;padding:0.6rem 1rem;cursor:pointer;border-radius:0.5rem;background:rgba(99,102,241,0.06);margin:0.3rem 0;transition:background 0.2s}\n')
out.write('.dns-type-header:hover{background:rgba(99,102,241,0.12)}\n')
out.write('.dns-type-badge{padding:0.15rem 0.5rem;border-radius:0.3rem;font-size:0.72rem;font-weight:bold;min-width:36px;text-align:center}\n')
out.write('.dns-type-A .dns-type-badge{background:rgba(96,165,250,0.2);color:#60a5fa}\n')
out.write('.dns-type-MX .dns-type-badge{background:rgba(251,146,60,0.2);color:#fdba74}\n')
out.write('.dns-type-NS .dns-type-badge{background:rgba(74,222,128,0.2);color:#4ade80}\n')
out.write('.dns-type-TXT .dns-type-badge{background:rgba(167,139,250,0.2);color:#a78bfa}\n')
out.write('.dns-type-SOA .dns-type-badge{background:rgba(248,113,113,0.2);color:#f87171}\n')
out.write('.dns-type-SRV .dns-type-badge{background:rgba(45,212,191,0.2);color:#2dd4bf}\n')
out.write('.dns-type-CNAME .dns-type-badge{background:rgba(251,191,36,0.2);color:#fbbf24}\n')
out.write('.dns-type-AAAA .dns-type-badge{background:rgba(129,140,248,0.2);color:#818cf8}\n')
out.write('.dns-records{display:none;padding:0.3rem 0 0.3rem 2.5rem}\n')
out.write('.dns-records.open{display:block}\n')
out.write('.dns-record{padding:0.35rem 0.8rem;font-size:0.8rem;border-left:2px solid rgba(99,102,241,0.2);margin:0.15rem 0;font-family:monospace;color:#cbd5e1}\n')
out.write('.dns-record .rec-name{color:#93c5fd}.dns-record .rec-val{color:#fca5a5}.dns-record .rec-target{color:#86efac}\n')
out.write('.dns-arrow{transition:transform 0.2s;color:#6366f1}.dns-arrow.open{transform:rotate(90deg)}\n')
out.write('.dns-count{font-size:0.7rem;color:#64748b}\n')
out.write('.spf-card{padding:1rem;border-radius:0.5rem;border-left:4px solid;margin:0.5rem 0}\n')
out.write('.spf-value{font-family:monospace;font-size:0.75rem;word-break:break-all;padding:0.5rem;border-radius:0.3rem;background:rgba(0,0,0,0.3);margin-top:0.5rem;color:#e2e8f0}\n')
out.write('.domain-section{margin-bottom:1.5rem}\n')
out.write('</style>\n')
out.write('</head><body>\n')
out.close()

# Nav
import subprocess
nav_html = subprocess.run(['bash', '-c', 'source ' + os.path.join(os.path.dirname(os.path.abspath(".")), "tool-web-dashboard.sh").replace("tool-web-dashboard.sh","") + '/tool-web-dashboard.sh 2>/dev/null; generate_nav dns 2>/dev/null || echo ""'], capture_output=True, text=True).stdout
# Fallback: write nav manually
out = open(os.path.join(DASHBOARD_DIR, "dns.html"), "a")

# Write nav manually since we can't source bash function from Python
out.write('<script src="assets/ai-status.js"></script>')
out.write(f'<nav><div class="container"><h1>W-BRID <span>— {h.escape(PRIMARY_DOMAIN)}</span></h1><div class="nav-links">')
out.write('<a href="index.html">Dashboard</a>')
out.write('<a href="subdomains.html">Subdomínios</a>')
out.write('<a href="brid-craftjs.html">Bird-Craft</a>')
out.write('<a data-ai-link class="ai-nav is-disabled">IA Findings</a>')
out.write('<a href="final-findings.html">Final Findings</a>')
out.write('<a href="urls.html">URLs</a>')
out.write('<a href="tree.html">Tree</a>')
out.write('<a href="dns.html" class="active">DNS</a>')
out.write('</div></div></nav>\n')

out.write('<div class="container">\n')
out.write(f'<div class="card"><h2>📡 DNS Analysis <span class="llm-badge">📊 Auto</span></h2>')
out.write(f'<p>Registros DNS de <strong>{len(by_domain)}</strong> domínios • <strong>{len(dns_records)}</strong> registros totais • dnsrecon + dnsenum</p></div>\n')

# --- SPF Section ---
if spf_findings:
    out.write('<div class="card"><h3>🛡️ SPF Policy Analysis</h3>\n')
    for spf in spf_findings:
        border_color = spf['color']
        out.write(f'<div class="spf-card" style="border-color:{border_color}">')
        out.write(f'<strong>{spf["icon"]} {h.escape(spf["domain"])}</strong> — <span style="color:{border_color}">{h.escape(spf["policy"])}</span>')
        out.write(f'<div class="spf-value">{h.escape(spf["value"])}</div>')
        out.write('</div>\n')
    out.write('</div>\n')

# --- DMARC Section ---
if dmarc_findings:
    out.write('<div class="card"><h3>📧 DMARC Records</h3>\n')
    for dm in dmarc_findings:
        out.write(f'<div class="spf-card" style="border-color:#a78bfa">')
        out.write(f'<strong>📧 {h.escape(dm["domain"])}</strong> — {h.escape(dm["name"])}')
        out.write(f'<div class="spf-value">{h.escape(dm["value"])}</div>')
        out.write('</div>\n')
    out.write('</div>\n')

# --- DNS Tree per domain ---
type_order = ['SOA', 'NS', 'A', 'AAAA', 'MX', 'CNAME', 'TXT', 'SRV']

for domain in sorted(by_domain.keys()):
    types = by_domain[domain]
    total = sum(len(v) for v in types.values())
    out.write(f'<div class="card domain-section"><h3>🌐 {h.escape(domain)} <span class="dns-count">({total} registros)</span></h3>\n')
    out.write('<div class="dns-tree">\n')

    # Sort types by predefined order
    sorted_types = sorted(types.keys(), key=lambda x: type_order.index(x) if x in type_order else 99)

    for rtype in sorted_types:
        records = types[rtype]
        # Deduplicate records
        seen = set()
        unique_records = []
        for r in records:
            key = (r.get('Name',''), r.get('Address',''), r.get('Target',''), r.get('String',''))
            if key not in seen:
                seen.add(key)
                unique_records.append(r)

        tid = f"dns-{h.escape(domain)}-{h.escape(rtype)}".replace(".", "-")
        out.write(f'<div class="dns-type-{h.escape(rtype)}">')
        out.write(f'<div class="dns-type-header" onclick="var r=document.getElementById(\'{tid}\');r.classList.toggle(\'open\');this.querySelector(\'.dns-arrow\').classList.toggle(\'open\')">')
        out.write(f'<span class="dns-arrow">▶</span>')
        out.write(f'<span class="dns-type-badge">{h.escape(rtype)}</span>')
        out.write(f'<span style="color:#e2e8f0">{h.escape(rtype)} Records</span>')
        out.write(f'<span class="dns-count">{len(unique_records)}</span>')
        out.write('</div>')
        out.write(f'<div id="{tid}" class="dns-records">')

        for r in unique_records:
            name = r.get('Name', '')
            addr = r.get('Address', '')
            target = r.get('Target', '')
            string = r.get('String', '')
            port = r.get('Port', '')
            display = ''
            if name:
                display += f'<span class="rec-name">{h.escape(name)}</span> '
            if addr:
                display += f'→ <span class="rec-val">{h.escape(addr)}</span> '
            if target:
                display += f'→ <span class="rec-target">{h.escape(target)}</span> '
            if port:
                display += f':{h.escape(str(port))} '
            if string:
                display += f'<span style="color:#a78bfa">{h.escape(string[:120])}</span>'
            out.write(f'<div class="dns-record">{display}</div>\n')

        out.write('</div></div>\n')

    out.write('</div></div>\n')

out.write('</div>\n')
out.write('<script src="assets/script.js"></script></body></html>\n')
out.close()
print(f"[DNS] Generated dns.html with {len(dns_records)} records from {len(by_domain)} domains")
PYEOF
}

main "$@"
