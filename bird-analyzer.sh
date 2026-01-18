#!/bin/bash

# Bird Tool Web Analyzer - Dashboard Generator
# Script para processar outputs de ferramentas de segurança e gerar dashboard HTML

set -e

# Cores para output no terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Diretórios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/OUT-WEB-BIRD"
DASHBOARD_DIR="${SCRIPT_DIR}/dashboard"
ASSETS_DIR="${DASHBOARD_DIR}/assets"

# Arquivos temporários para armazenar dados agregados
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

SUBDOMAINS_FILE="${TEMP_DIR}/subdomains.txt"
IPV4_FILE="${TEMP_DIR}/ipv4.txt"
URLS_FILE="${TEMP_DIR}/urls.txt"
VULNS_FILE="${TEMP_DIR}/vulnerabilities.json"
AMASS_FILE="${TEMP_DIR}/amass.json"
FIERCE_FILE="${TEMP_DIR}/fierce.json"
BRID_FILE="${TEMP_DIR}/brid_craftjs.json"

# Funções de utilidade
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Função para extrair domínio base de um target
extract_base_domain() {
    local target="$1"
    echo "$target" | awk -F'.' '{print $(NF-1)"."$NF}'
}

# Função para parsear AMASS (formato: DADO --> TIPO --> DADO)
parse_amass() {
    local file="$1"
    local base_domain="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # Filtrar aaaa_record e processar o formato de 3 colunas
    grep -v "aaaa_record" "$file" 2>/dev/null | while IFS= read -r line; do
        if [[ "$line" =~ ^(.+)\ --\>\ ([a-z_]+)\ --\>\ (.+)$ ]]; then
            local source="${BASH_REMATCH[1]}"
            local record_type="${BASH_REMATCH[2]}"
            local destination="${BASH_REMATCH[3]}"
            
            # Adicionar subdomínios
            if [[ "$source" == *"$base_domain"* ]]; then
                echo "$source" >> "$SUBDOMAINS_FILE"
            fi
            if [[ "$destination" == *"$base_domain"* ]]; then
                echo "$destination" >> "$SUBDOMAINS_FILE"
            fi
            
            # Extrair IPs
            if [[ "$record_type" == "a_record" ]]; then
                echo "$destination" >> "$IPV4_FILE"
            fi
            
            # Armazenar dados do amass em JSON
            echo "{\"source\":\"$source\",\"type\":\"$record_type\",\"dest\":\"$destination\"}" >> "$AMASS_FILE"
        fi
    done
}

# Função para parsear Fierce
parse_fierce() {
    local file="$1"
    local base_domain="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # Extrair "Found:" entries que contém domínio e IP
    grep "^Found:" "$file" 2>/dev/null | while IFS= read -r line; do
        if [[ "$line" =~ Found:\ ([a-zA-Z0-9._-]+)\.\ \(([0-9.]+)\) ]]; then
            local domain="${BASH_REMATCH[1]}"
            local ip="${BASH_REMATCH[2]}"
            
            if [[ "$domain" == *"$base_domain"* ]]; then
                echo "$domain" >> "$SUBDOMAINS_FILE"
                echo "$ip" >> "$IPV4_FILE"
                echo "{\"domain\":\"$domain\",\"ip\":\"$ip\"}" >> "$FIERCE_FILE"
            fi
        fi
    done
}

# Função para parsear Nikto
parse_nikto() {
    local file="$1"
    local target="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # Extrair linhas que começam com "+"
    grep "^+ " "$file" 2>/dev/null | while IFS= read -r line; do
        # Escapar aspas e caracteres especiais para JSON
        local clean_line=$(echo "$line" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g')
        echo "{\"tool\":\"nikto\",\"target\":\"$target\",\"finding\":\"$clean_line\",\"severity\":\"medium\"}" >> "$VULNS_FILE"
    done
}

# Função para parsear Nuclei
parse_nuclei() {
    local file="$1"
    local target="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # Remover códigos ANSI e processar
    sed 's/\x1b\[[0-9;]*m//g' "$file" | grep -E '^\[.*\]' 2>/dev/null | while IFS= read -r line; do
        local severity="info"
        
        if echo "$line" | grep -qi "critical"; then
            severity="critical"
        elif echo "$line" | grep -qi "high"; then
            severity="high"
        elif echo "$line" | grep -qi "medium"; then
            severity="medium"
        elif echo "$line" | grep -qi "low"; then
            severity="low"
        fi
        
        local clean_line=$(echo "$line" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g')
        echo "{\"tool\":\"nuclei\",\"target\":\"$target\",\"finding\":\"$clean_line\",\"severity\":\"$severity\"}" >> "$VULNS_FILE"
    done
}

# Função para parsear Wapiti
parse_wapiti() {
    local file="$1"
    local target="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # Extrair informações de segurança
    grep -E "(is not set|vulnerability|Checking)" "$file" 2>/dev/null | while IFS= read -r line; do
        local clean_line=$(echo "$line" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g')
        echo "{\"tool\":\"wapiti\",\"target\":\"$target\",\"finding\":\"$clean_line\",\"severity\":\"low\"}" >> "$VULNS_FILE"
    done
}

# Função para parsear Hakrawler (URLs)
parse_hakrawler() {
    local file="$1"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    cat "$file" >> "$URLS_FILE"
}

# Função para parsear Assetfinder, Subfinder, Sublist3r
parse_subdomain_tool() {
    local file="$1"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    cat "$file" >> "$SUBDOMAINS_FILE"
}

# Função para parsear BRID-CRAFTJS
parse_brid_craftjs() {
    local target_dir="$1"
    local target=$(basename "$target_dir")
    local craftjs_file=""
    
    # Tentar encontrar arquivo (pode ser bird-craftjs ou bird-crafjs)
    for pattern in "${target_dir}/${target}-bird-craftjs" "${target_dir}/${target}-bird-crafjs"; do
        if [[ -f "$pattern" && -s "$pattern" ]]; then
            craftjs_file="$pattern"
            break
        fi
    done
    
    if [[ -z "$craftjs_file" ]]; then
        return
    fi
    
    local titulo=""
    local dado=""
    local url=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^TITULO:\ (.+)$ ]]; then
            titulo="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^DADO:\ (.+)$ ]]; then
            dado="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^URL:\ (.+)$ ]]; then
            url="${BASH_REMATCH[1]}"
            
            # Quando temos os 3 campos, salvar em JSON
            if [[ -n "$titulo" && -n "$dado" && -n "$url" ]]; then
                local clean_titulo=$(echo "$titulo" | sed 's/"/\\"/g')
                local clean_dado=$(echo "$dado" | sed 's/"/\\"/g')
                local clean_url=$(echo "$url" | sed 's/"/\\"/g')
                
                echo "{\"titulo\":\"$clean_titulo\",\"dado\":\"$clean_dado\",\"url\":\"$clean_url\"}" >> "$BRID_FILE"
                
                # Reset
                titulo=""
                dado=""
                url=""
            fi
        fi
    done < "$craftjs_file"
}

# Função para extrair emails de URLs
extract_emails_from_urls() {
    if [[ -f "$URLS_FILE" ]]; then
        # Extrair mailto: links e adicionar ao BRID_FILE como emails
        grep -oE 'mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$URLS_FILE" 2>/dev/null | \
        sed 's/mailto://' | sort -u | while read -r email; do
            echo "{\"titulo\":\"Email (URL)\",\"dado\":\"$email\",\"url\":\"Extracted from URLs\"}" >> "$BRID_FILE"
        done
    fi
}

# Função principal de processamento
process_targets() {
    log_info "Processando targets do diretório OUT-WEB-BIRD..."
    
    local total_targets=0
    local processed_targets=0
    
    # Contar total de targets
    total_targets=$(find "$OUT_DIR" -maxdepth 1 -type d | wc -l)
    total_targets=$((total_targets - 1)) # Excluir o próprio diretório OUT-WEB-BIRD
    
    log_info "Total de targets encontrados: $total_targets"
    
    for target_dir in "$OUT_DIR"/*; do
        if [[ ! -d "$target_dir" ]]; then
            continue
        fi
        
        local target=$(basename "$target_dir")
        local base_domain=$(extract_base_domain "$target")
        
        processed_targets=$((processed_targets + 1))
        log_info "[$processed_targets/$total_targets] Processando: $target"
        
        # Processar cada ferramenta
        parse_amass "${target_dir}/${target}-amass" "$base_domain"
        parse_fierce "${target_dir}/${target}-fierce" "$base_domain"
        parse_nikto "${target_dir}/${target}-nikto" "$target"
        parse_nuclei "${target_dir}/${target}-nuclei" "$target"
        parse_wapiti "${target_dir}/${target}-wapiti" "$target"
        parse_hakrawler "${target_dir}/${target}-hakrawler"
        parse_subdomain_tool "${target_dir}/${target}-assetfinder"
        parse_subdomain_tool "${target_dir}/${target}-subfinder"
        parse_subdomain_tool "${target_dir}/${target}-sublist3r"
        parse_brid_craftjs "$target_dir"
    done
    
    log_success "Processamento concluído!"
}

# Função para limpar dados
clean_data() {
    log_info "Limpando dados..."
    
    # Limpar IPs - remover "(IPAddress)" e espaços extras
    if [[ -f "$IPV4_FILE" ]]; then
        sed -i 's/ (IPAddress)//g; s/(IPAddress)//g' "$IPV4_FILE"
        # Remover linhas vazias e espaços
        sed -i '/^$/d; s/^[[:space:]]*//; s/[[:space:]]*$//' "$IPV4_FILE"
    fi
    
    # Limpar Subdomínios - remover "(FQDN)" e espaços extras
    if [[ -f "$SUBDOMAINS_FILE" ]]; then
        sed -i 's/ (FQDN)//g; s/(FQDN)//g' "$SUBDOMAINS_FILE"
        # Remover linhas vazias e espaços
        sed -i '/^$/d; s/^[[:space:]]*//; s/[[:space:]]*$//' "$SUBDOMAINS_FILE"
    fi
    
    # Extrair emails das URLs
    extract_emails_from_urls
    
    log_success "Dados limpos"
}

# Função para gerar estatísticas
generate_statistics() {
    log_info "Gerando estatísticas..."
    
    # Primeiro limpar os dados
    clean_data
    
    # Eliminar duplicatas e contar (usando tr para remover espaços)
    local total_subdomains=$(sort -u "$SUBDOMAINS_FILE" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
    local total_ipv4=$(sort -u "$IPV4_FILE" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
    local total_urls=$(sort -u "$URLS_FILE" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
    local total_vulns=$(wc -l < "$VULNS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    local total_brid=$(wc -l < "$BRID_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${TEMP_DIR}/stats.json" <<EOF
{"total_subdomains":$total_subdomains,"total_ipv4":$total_ipv4,"total_urls":$total_urls,"total_vulnerabilities":$total_vulns,"total_brid_findings":$total_brid,"generated_at":"$(date -Iseconds)"}
EOF
    
    log_success "Estatísticas geradas: $total_subdomains subdomínios, $total_ipv4 IPs, $total_urls URLs, $total_vulns vulnerabilidades, $total_brid BRID findings"
}

# Inicializar arquivos
init_files() {
    log_info "Inicializando estrutura de diretórios..."
    
    mkdir -p "$DASHBOARD_DIR"
    mkdir -p "$ASSETS_DIR"
    
    touch "$SUBDOMAINS_FILE"
    touch "$IPV4_FILE"
    touch "$URLS_FILE"
    touch "$VULNS_FILE"
    touch "$AMASS_FILE"
    touch "$FIERCE_FILE"
    touch "$BRID_FILE"
    
    log_success "Estrutura inicializada"
}

# Função para gerar navegação comum
generate_nav() {
    local current_page="${1:-index}"
    cat <<'EOFNAV'
    <nav>
        <div class="container">
            <h1>🦅 Bird Tool Web Analyzer</h1>
            <div class="nav-links">
                <a href="index.html">Dashboard</a>
                <a href="subdomains.html">Subdomínios</a>
                <a href="ipv4.html">IPv4</a>
                <a href="vulnerabilities.html">Vulnerabilidades</a>
                <a href="brid-craftjs.html">BRID-CRAFTJS</a>
                <a href="amass.html">AMASS</a>
                <a href="fierce.html">Fierce</a>
                <a href="urls.html">URLs</a>
            </div>
        </div>
    </nav>
EOFNAV
}

# Gerar index.html
generate_index_html() {
    local stats=$(cat "${TEMP_DIR}/stats.json")
    # Usar sed para extrair valores numéricos corretamente
    local total_subdomains=$(echo "$stats" | sed -n 's/.*"total_subdomains":\([0-9]*\).*/\1/p')
    local total_ipv4=$(echo "$stats" | sed -n 's/.*"total_ipv4":\([0-9]*\).*/\1/p')
    local total_urls=$(echo "$stats" | sed -n 's/.*"total_urls":\([0-9]*\).*/\1/p')
    local total_vulns=$(echo "$stats" | sed -n 's/.*"total_vulnerabilities":\([0-9]*\).*/\1/p')
    local total_brid=$(echo "$stats" | sed -n 's/.*"total_brid_findings":\([0-9]*\).*/\1/p')
    local generated_at=$(echo "$stats" | sed -n 's/.*"generated_at":"\([^"]*\)".*/\1/p')
    
    # Gerar top 5 vulnerabilidades para sumário executivo
    local top_vulns_html=""
    if [[ -f "$VULNS_FILE" && -s "$VULNS_FILE" ]]; then
        # Priorizar critical > high > medium
        top_vulns_html=$(grep -E '"severity":"(critical|high|medium)"' "$VULNS_FILE" 2>/dev/null | head -5 | while read -r line; do
            local tool=$(echo "$line" | grep -o '"tool":"[^"]*"' | cut -d'"' -f4)
            local target=$(echo "$line" | grep -o '"target":"[^"]*"' | cut -d'"' -f4)
            local severity=$(echo "$line" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4)
            local finding=$(echo "$line" | grep -o '"finding":"[^"]*"' | cut -d'"' -f4 | head -c 100)
            echo "<tr><td><span class=\"severity-$severity\">$severity</span></td><td><code>$tool</code></td><td><a href=\"https://$target\" target=\"_blank\" style=\"color:#60a5fa\">$target</a></td><td>$finding...</td></tr>"
        done)
    fi
    
    # Contar por severidade (garantir número limpo)
    local count_critical=$(grep -c '"severity":"critical"' "$VULNS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    local count_high=$(grep -c '"severity":"high"' "$VULNS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    local count_medium=$(grep -c '"severity":"medium"' "$VULNS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    local count_low=$(grep -c '"severity":"low"' "$VULNS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    
    # Contar tipos de BRID findings
    local count_emails=$(grep -c '"titulo":"Email' "$BRID_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    local count_creds=$(grep -c '"titulo":"Credential' "$BRID_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    local count_api=$(grep -c '"titulo":"API' "$BRID_FILE" 2>/dev/null | tr -d '\n' || echo "0")
    
    cat > "${DASHBOARD_DIR}/index.html" <<EOFHTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bird Tool Web Analyzer - Dashboard</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    $(generate_nav 'index')
    
    <div class="container">
        <div class="card">
            <h2>📊 Dashboard de Segurança - Sumário Executivo</h2>
            <p>Análise completa de ferramentas de reconhecimento e segurança web</p>
            <p><small>Gerado em: ${generated_at}</small></p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">${total_subdomains}</div>
                <div class="stat-label">Subdomínios</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${total_ipv4}</div>
                <div class="stat-label">Endereços IPv4</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${total_urls}</div>
                <div class="stat-label">URLs Descobertas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${total_vulns}</div>
                <div class="stat-label">Vulnerabilidades</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${total_brid}</div>
                <div class="stat-label">BRID-CRAFTJS Findings</div>
            </div>
        </div>
        
        <div class="card" style="border-left: 4px solid #ef4444;">
            <h3>🚨 Top 5 Vulnerabilidades (Executivo)</h3>
            <p>Principais achados de segurança que requerem atenção imediata:</p>
            <div class="stats-grid" style="margin: 1rem 0;">
                <div style="text-align:center;"><span class="severity-critical" style="font-size:1.2rem;padding:0.5rem 1rem;">$count_critical Critical</span></div>
                <div style="text-align:center;"><span class="severity-high" style="font-size:1.2rem;padding:0.5rem 1rem;">$count_high High</span></div>
                <div style="text-align:center;"><span class="severity-medium" style="font-size:1.2rem;padding:0.5rem 1rem;">$count_medium Medium</span></div>
                <div style="text-align:center;"><span class="severity-low" style="font-size:1.2rem;padding:0.5rem 1rem;">$count_low Low/Info</span></div>
            </div>
            <div class="table-container" style="margin-top:1rem;">
                <table>
                    <thead>
                        <tr><th>Severidade</th><th>Ferramenta</th><th>Target</th><th>Descrição</th></tr>
                    </thead>
                    <tbody>
                        $top_vulns_html
                    </tbody>
                </table>
            </div>
            <p style="margin-top:1rem;"><a href="vulnerabilities.html" class="link-btn">Ver todas as vulnerabilidades →</a></p>
        </div>
        
        <div class="card" style="border-left: 4px solid #f59e0b;">
            <h3>🔑 BRID-CRAFTJS - Dados Sensíveis Expostos</h3>
            <p>Resumo de dados sensíveis encontrados em arquivos JavaScript:</p>
            <div class="stats-grid" style="margin: 1rem 0;">
                <div style="text-align:center;background:rgba(239,68,68,0.1);padding:1rem;border-radius:0.5rem;">
                    <div style="font-size:2rem;font-weight:bold;color:#fca5a5;">$count_emails</div>
                    <div>Emails</div>
                </div>
                <div style="text-align:center;background:rgba(239,68,68,0.1);padding:1rem;border-radius:0.5rem;">
                    <div style="font-size:2rem;font-weight:bold;color:#fca5a5;">$count_creds</div>
                    <div>Credentials</div>
                </div>
                <div style="text-align:center;background:rgba(239,68,68,0.1);padding:1rem;border-radius:0.5rem;">
                    <div style="font-size:2rem;font-weight:bold;color:#fca5a5;">$count_api</div>
                    <div>API Routes</div>
                </div>
            </div>
            <p><a href="brid-craftjs.html" class="link-btn">Ver todos os achados BRID-CRAFTJS →</a></p>
        </div>
        
        <div class="card">
            <h3>🔍 Descrição das Análises</h3>
            <p><strong>Subdomínios:</strong> Total de subdomínios únicos descobertos por todas as ferramentas (amass, assetfinder, subfinder, sublist3r, fierce, dnsenum, dnsrecon).</p>
            <p><strong>IPv4:</strong> Endereços IPv4 únicos extraídos das análises de DNS e enumeração.</p>
            <p><strong>URLs:</strong> Links e endpoints descobertos durante o crawling e análise.</p>
            <p><strong>Vulnerabilidades:</strong> Problemas de segurança identificados por Nikto, Nuclei, Wapiti e Fierce.</p>
            <p><strong>BRID-CRAFTJS:</strong> Dados sensíveis e senhas encontradas em arquivos JavaScript.</p>
        </div>
        
        <div class="card">
            <h3>🛠️ Ferramentas Utilizadas</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                <div><code>amass</code> - Enumeração DNS</div>
                <div><code>assetfinder</code> - Descoberta de assets</div>
                <div><code>dnsenum</code> - Análise DNS</div>
                <div><code>dnsrecon</code> - Reconhecimento DNS</div>
                <div><code>fierce</code> - Scan DNS</div>
                <div><code>hakrawler</code> - Web crawler</div>
                <div><code>nikto</code> - Scan de vulnerabilidades</div>
                <div><code>nuclei</code> - Template-based scanning</div>
                <div><code>subfinder</code> - Subdomain discovery</div>
                <div><code>sublist3r</code> - Subdomain enumeration</div>
                <div><code>wapiti</code> - Web application scanner</div>
                <div><code>BRID-CRAFTJS</code> - Análise de JavaScript</div>
            </div>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Gerar subdomains.html
generate_subdomains_html() {
    local subdomains=$(sort -u "$SUBDOMAINS_FILE" 2>/dev/null | grep -v '^$' | sed 's/ (FQDN)//g')
    local count=$(echo "$subdomains" | grep -v '^$' | wc -l | tr -d ' ')
    
    cat > "${DASHBOARD_DIR}/subdomains.html" <<EOFHTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomínios - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
    <style>
        .dork-select {
            padding: 0.4rem;
            background: linear-gradient(135deg, #10b981, #059669);
            border: none;
            border-radius: 0.5rem;
            color: white;
            font-size: 0.8rem;
            cursor: pointer;
            margin: 0.2rem;
        }
        .dork-select:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(16, 185, 129, 0.4);
        }
    </style>
</head>
<body>
    $(generate_nav 'subdomains')
    
    <div class="container">
        <div class="card">
            <h2>🌐 Subdomínios Descobertos</h2>
            <p>Total: <strong id="visibleCount">$count</strong> subdomínios únicos</p>
            <p style="font-size: 0.85rem; color: #94a3b8;">Clique no subdomínio para abrir em nova aba. Use o seletor de Google Dorks para pesquisar informações adicionais.</p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar subdomínios...">
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Subdomínio</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    local index=1
    echo "$subdomains" | grep -v '^$' | while read -r subdomain; do
        # Limpar subdomain de caracteres extras
        subdomain=$(echo "$subdomain" | sed 's/ (FQDN)//g; s/^[[:space:]]*//; s/[[:space:]]*$//')
        
        # Escapar caracteres especiais para URLs
        local encoded_subdomain=$(echo "$subdomain" | sed 's/ /%20/g')
        
        cat >> "${DASHBOARD_DIR}/subdomains.html" <<EOFROW
                    <tr>
                        <td>$index</td>
                        <td><a href="https://$subdomain" target="_blank" style="color: #60a5fa; text-decoration: none;"><code>$subdomain</code></a></td>
                        <td>
                            <a href="https://who.is/whois/$encoded_subdomain" target="_blank" class="link-btn">WHOIS</a>
                            <a href="https://urlscan.io/search/#$encoded_subdomain" target="_blank" class="link-btn">URLScan.io</a>
                            <select class="dork-select" onchange="if(this.value)window.open(this.value,'_blank');this.selectedIndex=0;">
                                <option value="">🔍 Google Dorks</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain">site:domain</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:pdf">PDF files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:doc+OR+filetype:docx">DOC files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:xls+OR+filetype:xlsx">XLS files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:sql+OR+filetype:bak">SQL/Backup files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:log">Log files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:xml">XML files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:conf+OR+filetype:cfg">Config files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:admin">Admin pages</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:login">Login pages</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:api">API endpoints</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+intitle:index+of">Directory listing</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+ext:env+OR+ext:git">Sensitive files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+password+OR+senha+OR+pwd">Passwords</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:wp-content">WordPress</option>
                            </select>
                        </td>
                    </tr>
EOFROW
        index=$((index + 1))
    done
    
    cat >> "${DASHBOARD_DIR}/subdomains.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Verificar se diretório OUT-WEB-BIRD existe
check_requirements() {
    if [[ ! -d "$OUT_DIR" ]]; then
        log_error "Diretório OUT-WEB-BIRD não encontrado em: $OUT_DIR"
        exit 1
    fi
    
    log_success "Diretório OUT-WEB-BIRD encontrado"
}

# Função para gerar HTML files
generate_html_files() {
    log_info "Gerando arquivos HTML..."
    
    # Source auxiliary generators
    source "${SCRIPT_DIR}/html_generators.sh"
    
    # Gerar assets (CSS e JS)
    generate_css
    generate_js
    
    # Gerar páginas HTML
    generate_index_html
    generate_subdomains_html
    generate_ipv4_html
    generate_vulnerabilities_html
    generate_brid_html
    generate_amass_html
    generate_fierce_html
    generate_urls_html
    
    log_success "Arquivos HTML gerados"
}

# Gerar CSS
generate_css() {
    cat > "${ASSETS_DIR}/style.css" << 'EOFCSS'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --primary: #6366f1;
    --secondary: #8b5cf6;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --info: #3b82f6;
    --dark: #1e293b;
    --darker: #0f172a;
    --light: #f8fafc;
    --gray: #64748b;
    --border: #334155;
}

body {
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    background: linear-gradient(135deg, var(--darker) 0%, #1a1f2e 100%);
    color: var(--light);
    min-height: 100vh;
    line-height: 1.6;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
}

/* Navigation */
nav {
    background: rgba(30, 41, 59, 0.8);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border);
    padding: 1rem 0;
    position: sticky;
    top: 0;
    z-index: 1000;
}

nav .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0 2rem;
}

nav h1 {
    font-size: 1.5rem;
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

nav .nav-links {
    display: flex;
    gap: 1rem;
    list-style: none;
    flex-wrap: wrap;
}

nav .nav-links a {
    color: var(--light);
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    transition: all 0.3s ease;
    font-size: 0.9rem;
}

nav .nav-links a:hover {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    transform: translateY(-2px);
}

/* Cards */
.card {
    background: rgba(30, 41, 59, 0.6);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border);
    border-radius: 1rem;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    transition: all 0.3s ease;
}

.card:hover {
    transform: translateY(-4px);
    box-shadow: 0 10px 30px rgba(99, 102, 241, 0.2);
    border-color: var(--primary);
}

.card h2, .card h3 {
    margin-bottom: 1rem;
    color: var(--light);
}

/* Stats Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.stat-card {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(139, 92, 246, 0.1));
    border: 1px solid var(--primary);
    border-radius: 1rem;
    padding: 1.5rem;
    text-align: center;
    transition: all 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-4px) scale(1.02);
    box-shadow: 0 10px 30px rgba(99, 102, 241, 0.3);
}

.stat-card .stat-number {
    font-size: 2.5rem;
    font-weight: bold;
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
}

.stat-card .stat-label {
    color: var(--gray);
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* Table */
.table-container {
    overflow-x: auto;
    border-radius: 1rem;
    background: rgba(30, 41, 59, 0.6);
    border: 1px solid var(--border);
}

table {
    width: 100%;
    border-collapse: collapse;
}

thead {
    background: rgba(99, 102, 241, 0.1);
    border-bottom: 2px solid var(--primary);
}

thead th {
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    color: var(--light);
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

tbody tr {
    border-bottom: 1px solid var(--border);
    transition: all 0.2s ease;
}

tbody tr:hover {
    background: rgba(99, 102, 241, 0.05);
}

tbody td {
    padding: 1rem;
    color: var(--light);
    font-size: 0.9rem;
}

/* Links */
.link-btn {
    display: inline-block;
    padding: 0.4rem 0.8rem;
    margin: 0.2rem;
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white;
    text-decoration: none;
    border-radius: 0.5rem;
    font-size: 0.8rem;
    transition: all 0.3s ease;
}

.link-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(99, 102, 241, 0.4);
}

/* Filters */
.filter-bar {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.filter-bar input,
.filter-bar select {
    padding: 0.75rem 1rem;
    background: rgba(30, 41, 59, 0.8);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    color: var(--light);
    font-size: 0.9rem;
    transition: all 0.3s ease;
    flex: 1;
    min-width: 200px;
}

.filter-bar input:focus,
.filter-bar select:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
}

/* Severity badges */
.severity-critical {
    background: var(--danger);
    color: white;
    padding: 0.3rem 0.8rem;
    border-radius: 1rem;
    font-size: 0.8rem;
    font-weight: 600;
}

.severity-high {
    background: var(--warning);
    color: white;
    padding: 0.3rem 0.8rem;
    border-radius: 1rem;
    font-size: 0.8rem;
    font-weight: 600;
}

.severity-medium {
    background: var(--info);
    color: white;
    padding: 0.3rem 0.8rem;
    border-radius: 1rem;
    font-size: 0.8rem;
    font-weight: 600;
}

.severity-low,
.severity-info {
    background: var(--gray);
    color: white;
    padding: 0.3rem 0.8rem;
    border-radius: 1rem;
    font-size: 0.8rem;
    font-weight: 600;
}

/* Code blocks */
code {
    background: rgba(0, 0, 0, 0.3);
    padding: 0.2rem 0.5rem;
    border-radius: 0.3rem;
    font-family: 'Courier New', monospace;
    font-size: 0.85rem;
    color: #a5f3fc;
}

/* Responsive */
@media (max-width: 768px) {
    nav .container {
        flex-direction: column;
        gap: 1rem;
    }
    
    nav .nav-links {
        justify-content: center;
    }
    
    .stats-grid {
        grid-template-columns: 1fr;
    }
}
EOFCSS
}

# Gerar JavaScript
generate_js() {
    cat > "${ASSETS_DIR}/script.js" << 'EOFJS'
// Filter and search functionality
function initializeFilters() {
    const searchInput = document.getElementById('searchInput');
    const filterSelect = document.getElementById('filterSelect');
    const table = document.querySelector('table tbody');
    
    if (!table) return;
    
    const rows = Array.from(table.getElementsByTagName('tr'));
    
    function filterRows() {
        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        const filterValue = filterSelect ? filterSelect.value.toLowerCase() : '';
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const matchesSearch = text.includes(searchTerm);
            const matchesFilter = !filterValue || text.includes(filterValue);
            
            row.style.display = (matchesSearch && matchesFilter) ? '' : 'none';
        });
        
        updateVisibleCount();
    }
    
    function updateVisibleCount() {
        const visibleRows = rows.filter(row => row.style.display !== 'none');
        const countElement = document.getElementById('visibleCount');
        if (countElement) {
            countElement.textContent = visibleRows.length;
        }
    }
    
    if (searchInput) {
        searchInput.addEventListener('input', filterRows);
    }
    
    if (filterSelect) {
        filterSelect.addEventListener('change', filterRows);
    }
    
    updateVisibleCount();
}

// Sort table
function sortTable(columnIndex) {
    const table = document.querySelector('table');
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.getElementsByTagName('tr'));
    
    rows.sort((a, b) => {
        const aText = a.getElementsByTagName('td')[columnIndex].textContent;
        const bText = b.getElementsByTagName('td')[columnIndex].textContent;
        return aText.localeCompare(bText);
    });
    
    rows.forEach(row => tbody.appendChild(row));
}

// Export to CSV
function exportToCSV() {
    const table = document.querySelector('table');
    if (!table) return;
    
    let csv = [];
    const rows = table.querySelectorAll('tr');
    
    rows.forEach(row => {
        const cols = row.querySelectorAll('td, th');
        const rowData = Array.from(cols).map(col => {
            let data = col.textContent.replace(/"/g, '""');
            return `"${data}"`;
        });
        csv.push(rowData.join(','));
    });
    
    const csvContent = csv.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bird-tool-export.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeFilters();
    
    // Add export button if table exists
    const table = document.querySelector('table');
    if (table) {
        const filterBar = document.querySelector('.filter-bar');
        if (filterBar) {
            const exportBtn = document.createElement('button');
            exportBtn.textContent = 'Export CSV';
            exportBtn.className = 'link-btn';
            exportBtn.onclick = exportToCSV;
            filterBar.appendChild(exportBtn);
        }
    }
});
EOFJS
}

# Main
main() {
    echo "================================================"
    echo "  Bird Tool Web Analyzer - Dashboard Generator"
    echo "================================================"
    echo ""
    
    check_requirements
    init_files
    process_targets
    generate_statistics
    
    log_info "Gerando dashboard HTML..."
    generate_html_files
    
    log_success "Dashboard gerado com sucesso em: $DASHBOARD_DIR"
    log_info "Abra o arquivo: $DASHBOARD_DIR/index.html"
}

# Executar
main "$@"
