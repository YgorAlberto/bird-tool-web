#!/bin/bash

# Bird Tool Web Analyzer - Dashboard Generator
# Script para processar outputs de ferramentas de segurança e gerar dashboard HTML
# Uso: ./bird-analyzer.sh [--skip-validation] [--skip-subdomain-validation]

# Opções de linha de comando
SKIP_URL_VALIDATION=false
SKIP_SUBDOMAIN_VALIDATION=false

for arg in "$@"; do
    case $arg in
        --skip-validation)
            SKIP_URL_VALIDATION=true
            shift
            ;;
        --skip-subdomain-validation)
            SKIP_SUBDOMAIN_VALIDATION=true
            shift
            ;;
        --skip-all)
            SKIP_URL_VALIDATION=true
            SKIP_SUBDOMAIN_VALIDATION=true
            shift
            ;;
        --help|-h)
            echo "Uso: ./bird-analyzer.sh [opções]"
            echo ""
            echo "Opções:"
            echo "  --skip-validation            Pular validação HTTP de URLs (mais rápido)"
            echo "  --skip-subdomain-validation  Pular validação DNS de subdomínios"
            echo "  --skip-all                   Pular todas as validações (mais rápido)"
            echo "  --help, -h                   Mostrar esta mensagem de ajuda"
            exit 0
            ;;
    esac
done

# Remover set -e para evitar que o script pare em erros de comandos individuais
# set -e

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
VALIDATED_URLS_FILE="${TEMP_DIR}/validated_urls.json"
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

# Função para parsear URLFINDER (URLs)
parse_urlfinder() {
    local file="$1"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # URLFINDER normalmente retorna URLs uma por linha
    grep -E '^https?://' "$file" 2>/dev/null >> "$URLS_FILE"
}

# Função para parsear WAYBACKURL (URLs do Wayback Machine)
parse_waybackurl() {
    local file="$1"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # WAYBACKURL retorna URLs históricas do archive.org
    grep -E '^https?://' "$file" 2>/dev/null >> "$URLS_FILE"
}

# Função para parsear DNSenum
parse_dnsenum() {
    local file="$1"
    local base_domain="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # Extrair subdomínios (linhas que contêm domínios)
    grep -oE "[a-zA-Z0-9][-a-zA-Z0-9]*\.$base_domain" "$file" 2>/dev/null | \
    while read -r subdomain; do
        echo "$subdomain" >> "$SUBDOMAINS_FILE"
    done
    
    # Extrair IPs (formato: IP Address: x.x.x.x ou linhas com IPs)
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" 2>/dev/null | \
    while read -r ip; do
        # Validar que é um IP válido (não começando com 0)
        if [[ ! "$ip" =~ ^0\. && "$ip" != "0.0.0.0" && "$ip" != "127.0.0.1" ]]; then
            echo "$ip" >> "$IPV4_FILE"
        fi
    done
}

# Função para parsear DNSrecon
parse_dnsrecon() {
    local file="$1"
    local base_domain="$2"
    
    if [[ ! -f "$file" || ! -s "$file" ]]; then
        return
    fi
    
    # DNSrecon pode ter formato JSON ou texto, processar texto
    # Extrair subdomínios
    grep -oE "[a-zA-Z0-9][-a-zA-Z0-9]*\.$base_domain" "$file" 2>/dev/null | \
    while read -r subdomain; do
        echo "$subdomain" >> "$SUBDOMAINS_FILE"
    done
    
    # Extrair IPs
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" 2>/dev/null | \
    while read -r ip; do
        if [[ ! "$ip" =~ ^0\. && "$ip" != "0.0.0.0" && "$ip" != "127.0.0.1" ]]; then
            echo "$ip" >> "$IPV4_FILE"
        fi
    done
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
            echo "{\"titulo\":\"Email (URL)\",\"dado\":\"$email\",\"url\":\"Extracted from mailto: links\"}" >> "$BRID_FILE"
        done
        
        # Também extrair emails em formato regular de todas URLs (ex: user@domain.com em parâmetros)
        grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$URLS_FILE" 2>/dev/null | \
        sort -u | while read -r email; do
            # Verificar se já não foi adicionado
            if ! grep -q "\"dado\":\"$email\"" "$BRID_FILE" 2>/dev/null; then
                echo "{\"titulo\":\"Email (URL)\",\"dado\":\"$email\",\"url\":\"Extracted from URL parameters\"}" >> "$BRID_FILE"
            fi
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
        
        # Processar ferramentas adicionais de URLs
        parse_urlfinder "${target_dir}/${target}-URL-urlfinder"
        parse_urlfinder "${target_dir}/${target}-urlfinder"
        parse_urlfinder "${target_dir}/${target}-URLFINDER"
        parse_waybackurl "${target_dir}/${target}-URL-waybackurls"
        parse_waybackurl "${target_dir}/${target}-waybackurl"
        parse_waybackurl "${target_dir}/${target}-WAYBACKURL"
        parse_dnsenum "${target_dir}/${target}-dnsenum" "$base_domain"
        parse_dnsrecon "${target_dir}/${target}-dnsrecon" "$base_domain"
    done
    
    log_success "Processamento concluído!"
}

# Função para validar uma única URL e retornar o código HTTP
validate_single_url() {
    local url="$1"
    local output_file="$2"
    
    # Timeout de 10 segundos, seguir redirects, apenas HEAD request
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 \
        --max-time 10 \
        -L \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        "$url" 2>/dev/null)
    
    # Se retornou um código HTTP válido (não 000)
    if [[ "$http_code" != "000" && -n "$http_code" ]]; then
        # Escapar URL para JSON
        local clean_url=$(echo "$url" | sed 's/\\/\\\\/g; s/"/\\"/g')
        echo "{\"url\":\"$clean_url\",\"status\":$http_code}" >> "$output_file"
    fi
}

# Exportar função para uso com xargs
export -f validate_single_url

# Função para validar todas as URLs coletadas
validate_urls() {
    log_info "Validando URLs (verificando códigos HTTP)..."
    
    if [[ ! -f "$URLS_FILE" || ! -s "$URLS_FILE" ]]; then
        log_warn "Nenhuma URL encontrada para validar"
        return 0
    fi
    
    # Criar arquivo de saída
    > "$VALIDATED_URLS_FILE"
    
    # Criar lista única de URLs
    local temp_urls="${TEMP_DIR}/unique_urls.txt"
    sort -u "$URLS_FILE" | grep -E '^https?://' > "$temp_urls" 2>/dev/null || true
    
    local total_urls=$(wc -l < "$temp_urls" 2>/dev/null | tr -d ' ')
    if [[ "$total_urls" == "0" || -z "$total_urls" ]]; then
        log_warn "Nenhuma URL HTTP/HTTPS encontrada"
        return 0
    fi
    
    log_info "Total de $total_urls URLs únicas para validar..."
    
    local count=0
    
    while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        
        # Mostrar progresso a cada 20 URLs
        if (( count % 20 == 0 )); then
            log_info "Progresso: $count/$total_urls URLs verificadas..."
        fi
        
        # Verificar URL de forma síncrona para capturar o código corretamente
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 3 \
            --max-time 5 \
            -L \
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            "$url" 2>/dev/null) || http_code="000"
        
        # Se retornou um código HTTP válido (não 000)
        if [[ "$http_code" != "000" && -n "$http_code" ]]; then
            local clean_url=$(echo "$url" | sed 's/\\/\\\\/g; s/"/\\"/g')
            echo "{\"url\":\"$clean_url\",\"status\":$http_code}" >> "$VALIDATED_URLS_FILE"
        fi
        
    done < "$temp_urls"
    
    local validated_count=$(wc -l < "$VALIDATED_URLS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    log_success "URLs validadas: $validated_count de $total_urls retornaram código HTTP válido"
}

# Função para validar subdomínios via DNS
validate_subdomains() {
    log_info "Validando subdomínios via DNS..."
    
    if [[ ! -f "$SUBDOMAINS_FILE" || ! -s "$SUBDOMAINS_FILE" ]]; then
        log_warn "Nenhum subdomínio encontrado para validar"
        return 0
    fi
    
    local temp_subs="${TEMP_DIR}/unique_subs.txt"
    local validated_subs="${TEMP_DIR}/validated_subs.txt"
    
    # Criar lista única de subdomínios
    sort -u "$SUBDOMAINS_FILE" | grep -v '^$' > "$temp_subs" 2>/dev/null || true
    > "$validated_subs"
    
    local total_subs=$(wc -l < "$temp_subs" 2>/dev/null | tr -d ' ')
    if [[ "$total_subs" == "0" || -z "$total_subs" ]]; then
        log_warn "Nenhum subdomínio válido encontrado"
        return 0
    fi
    
    log_info "Total de $total_subs subdomínios únicos para validar..."
    
    local count=0
    local valid=0
    
    while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
        count=$((count + 1))
        
        # Mostrar progresso a cada 50 subdomínios
        if (( count % 50 == 0 )); then
            log_info "Progresso: $count/$total_subs subdomínios verificados, $valid válidos..."
        fi
        
        # Verificar se o subdomínio resolve via DNS (timeout de 2s)
        if host -W 2 "$subdomain" >/dev/null 2>&1; then
            echo "$subdomain" >> "$validated_subs"
            valid=$((valid + 1))
        fi
        
    done < "$temp_subs"
    
    # Substituir arquivo original pelo validado
    if [[ -s "$validated_subs" ]]; then
        mv "$validated_subs" "$SUBDOMAINS_FILE"
    fi
    
    log_success "Subdomínios validados: $valid de $total_subs resolvem via DNS"
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
    
    # Limpar Subdomínios - remover "(FQDN)", espaços extras e códigos ANSI
    if [[ -f "$SUBDOMAINS_FILE" ]]; then
        # Remover códigos ANSI escape (cores do terminal)
        sed -i 's/\x1b\[[0-9;]*m//g; s/\[0m//g; s/0m//g' "$SUBDOMAINS_FILE"
        # Remover (FQDN), (IPAddress) e outros
        sed -i 's/ (FQDN)//g; s/(FQDN)//g; s/ (IPAddress)//g; s/(IPAddress)//g' "$SUBDOMAINS_FILE"
        # Remover linhas vazias e espaços
        sed -i '/^$/d; s/^[[:space:]]*//; s/[[:space:]]*$//' "$SUBDOMAINS_FILE"
        # Remover dados do VirusTotal (se houver)
        sed -i '/virustotal\.com/d' "$SUBDOMAINS_FILE"
        # Remover linhas que não parecem subdomínios válidos
        sed -i '/^[^a-zA-Z0-9]/d' "$SUBDOMAINS_FILE"
        # Remover linhas sem ponto (não são domínios)
        sed -i '/\./!d' "$SUBDOMAINS_FILE"
        # Remover caracteres inválidos no início
        sed -i 's/^[^a-zA-Z0-9]*//g' "$SUBDOMAINS_FILE"
    fi
    
    # Limpar IPs - remover códigos ANSI e caracteres extras
    if [[ -f "$IPV4_FILE" ]]; then
        sed -i 's/\x1b\[[0-9;]*m//g; s/\[0m//g; s/0m//g' "$IPV4_FILE"
        sed -i 's/ (IPAddress)//g; s/(IPAddress)//g' "$IPV4_FILE"
        sed -i '/^$/d; s/^[[:space:]]*//; s/[[:space:]]*$//' "$IPV4_FILE"
    fi
    
    # Limpar URLs - remover dados do VirusTotal e códigos ANSI
    if [[ -f "$URLS_FILE" ]]; then
        sed -i 's/\x1b\[[0-9;]*m//g; s/\[0m//g; s/0m//g' "$URLS_FILE"
        sed -i '/virustotal\.com/d' "$URLS_FILE"
    fi
    
    # Limpar Vulnerabilidades - remover entradas de log e duplicatas
    if [[ -f "$VULNS_FILE" ]]; then
        # Criar arquivo temporário para vulnerabilidades limpas
        local temp_vulns="${TEMP_DIR}/vulns_cleaned.json"
        
        # Filtrar linhas de log que não são vulnerabilidades
        grep -v -E '"finding":"(Start Time:|Checking|Target hostname|Target Port|\+ [0-9]+ host|Loading|Scan terminated|End Time:|Retrieved x-powered-by|Allowed HTTP Methods|Retrieved access-control)"' "$VULNS_FILE" 2>/dev/null | \
        grep -v -E '\[WRN\]|\[INF\]|host\(s\) tested|nikto-[0-9]+|Nikto v[0-9]' | \
        grep -v -E 'scan_id|Cookie .* created without' | \
        sort -u > "$temp_vulns" 2>/dev/null || true
        
        mv "$temp_vulns" "$VULNS_FILE" 2>/dev/null || true
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
    
    # Validar subdomínios via DNS (executado por padrão, pular com --skip-subdomain-validation)
    if [[ "$SKIP_SUBDOMAIN_VALIDATION" == "true" ]]; then
        log_warn "Validação de subdomínios pulada (--skip-subdomain-validation)"
    else
        validate_subdomains
    fi
    
    # Validar URLs (verificar códigos HTTP) - pode ser pulado com --skip-validation
    if [[ "$SKIP_URL_VALIDATION" == "true" ]]; then
        log_warn "Validação de URLs pulada (--skip-validation)"
        # Copiar URLs brutas para arquivo de URLs validadas (sem código HTTP)
        sort -u "$URLS_FILE" 2>/dev/null | grep -E '^https?://' | head -500 | while read -r url; do
            echo "{\"url\":\"$url\",\"status\":0}" >> "$VALIDATED_URLS_FILE"
        done
    else
        validate_urls
    fi
    
    # Eliminar duplicatas e contar (usando tr para remover espaços)
    local total_subdomains=$(sort -u "$SUBDOMAINS_FILE" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
    local total_ipv4=$(sort -u "$IPV4_FILE" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
    # Usar URLs validadas ao invés das URLs brutas
    local total_urls=$(wc -l < "$VALIDATED_URLS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    local total_vulns=$(wc -l < "$VULNS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    local total_brid=$(wc -l < "$BRID_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${TEMP_DIR}/stats.json" <<EOF
{"total_subdomains":$total_subdomains,"total_ipv4":$total_ipv4,"total_urls":$total_urls,"total_vulnerabilities":$total_vulns,"total_brid_findings":$total_brid,"generated_at":"$(date -Iseconds)"}
EOF
    
    log_success "Estatísticas geradas: $total_subdomains subdomínios, $total_ipv4 IPs, $total_urls URLs validadas, $total_vulns vulnerabilidades, $total_brid BRID findings"
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
            <a href="subdomains.html" class="stat-card-link">
                <div class="stat-card">
                    <div class="stat-number">${total_subdomains}</div>
                    <div class="stat-label">Subdomínios</div>
                    <div class="stat-action">Ver detalhes →</div>
                </div>
            </a>
            <a href="ipv4.html" class="stat-card-link">
                <div class="stat-card">
                    <div class="stat-number">${total_ipv4}</div>
                    <div class="stat-label">Endereços IPv4</div>
                    <div class="stat-action">Ver detalhes →</div>
                </div>
            </a>
            <a href="urls.html" class="stat-card-link">
                <div class="stat-card">
                    <div class="stat-number">${total_urls}</div>
                    <div class="stat-label">URLs Validadas</div>
                    <div class="stat-action">Ver detalhes →</div>
                </div>
            </a>
            <a href="vulnerabilities.html" class="stat-card-link">
                <div class="stat-card">
                    <div class="stat-number">${total_vulns}</div>
                    <div class="stat-label">Vulnerabilidades</div>
                    <div class="stat-action">Ver detalhes →</div>
                </div>
            </a>
            <a href="brid-craftjs.html" class="stat-card-link">
                <div class="stat-card">
                    <div class="stat-number">${total_brid}</div>
                    <div class="stat-label">BRID-CRAFTJS Findings</div>
                    <div class="stat-action">Ver detalhes →</div>
                </div>
            </a>
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
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:phpinfo">PHP Info</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:json+api">JSON API</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:.git">Git Files</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:swagger+OR+inurl:api-docs">Swagger/API Docs</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+ext:php+inurl:id%3D">SQL Injection</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+inurl:upload+OR+inurl:file">Upload Pages</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+intitle:error+OR+intitle:exception">Error Pages</option>
                                <option value="https://www.google.com/search?q=site:$encoded_subdomain+filetype:key+OR+filetype:pem">Certs/Keys</option>
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

# ============================================
# HTML GENERATORS (inline from html_generators.sh)
# ============================================

# Gerar ipv4.html
generate_ipv4_html() {
    local ipv4s=$(sort -u "$IPV4_FILE" 2>/dev/null | grep -v '^$')
    local count=$(echo "$ipv4s" | grep -v '^$' | wc -l | tr -d ' ')
    
    cat > "${DASHBOARD_DIR}/ipv4.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPv4 - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/ipv4.html"
    
    cat >> "${DASHBOARD_DIR}/ipv4.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>🔢 Endereços IPv4 Descobertos</h2>
            <p>Total: <strong id="visibleCount">$count</strong> IPs únicos</p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar IPs...">
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IPv4</th>
                        <th>Pesquisar em</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    local index=1
    echo "$ipv4s" | grep -v '^$' | while read -r ip; do
        local ip_base64=$(echo -n "ip=\"$ip\"" | base64 -w0)
        
        cat >> "${DASHBOARD_DIR}/ipv4.html" <<EOFROW
                    <tr>
                        <td>$index</td>
                        <td><code>$ip</code></td>
                        <td>
                            <a href="https://www.shodan.io/host/$ip" target="_blank" class="link-btn">Shodan</a>
                            <a href="https://search.censys.io/hosts/$ip" target="_blank" class="link-btn">Censys</a>
                            <a href="https://en.fofa.info/result?qbase64=$ip_base64" target="_blank" class="link-btn">FOFA</a>
                        </td>
                    </tr>
EOFROW
        index=$((index + 1))
    done
    
    cat >> "${DASHBOARD_DIR}/ipv4.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Gerar vulnerabilities.html
generate_vulnerabilities_html() {
    local count=$(wc -l < "$VULNS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${DASHBOARD_DIR}/vulnerabilities.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerabilidades - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/vulnerabilities.html"
    
    cat >> "${DASHBOARD_DIR}/vulnerabilities.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>🚨 Vulnerabilidades e Problemas de Segurança</h2>
            <p>Resultados agregados de Nikto, Nuclei, Wapiti e Fierce - Total: <strong id="visibleCount">$count</strong></p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar vulnerabilidades...">
            <select id="filterSelect">
                <option value="">Todas as Severidades</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
            </select>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Ferramenta</th>
                        <th>Target</th>
                        <th>Severidade</th>
                        <th>Descrição</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    if [[ -f "$VULNS_FILE" && -s "$VULNS_FILE" ]]; then
        while IFS= read -r line; do
            local tool=$(echo "$line" | grep -o '"tool":"[^"]*"' | cut -d'"' -f4)
            local target=$(echo "$line" | grep -o '"target":"[^"]*"' | cut -d'"' -f4)
            local severity=$(echo "$line" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4)
            local finding=$(echo "$line" | grep -o '"finding":".*"' | cut -d'"' -f4 | sed 's/\\"/"/g')
            
            cat >> "${DASHBOARD_DIR}/vulnerabilities.html" <<EOFROW
                    <tr>
                        <td><code>$tool</code></td>
                        <td><a href="https://$target" target="_blank" style="color: #60a5fa;"><code>$target</code></a></td>
                        <td><span class="severity-$severity">$severity</span></td>
                        <td>$finding</td>
                    </tr>
EOFROW
        done < "$VULNS_FILE"
    fi
    
    cat >> "${DASHBOARD_DIR}/vulnerabilities.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Gerar brid-craftjs.html
generate_brid_html() {
    local count=$(wc -l < "$BRID_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${DASHBOARD_DIR}/brid-craftjs.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BRID-CRAFTJS - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/brid-craftjs.html"
    
    cat >> "${DASHBOARD_DIR}/brid-craftjs.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>🔑 BRID-CRAFTJS - Dados Sensíveis em JavaScript</h2>
            <p>Senhas, tokens, emails e dados expostos encontrados em arquivos JS - Total: <strong id="visibleCount">$count</strong></p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar...">
            <select id="filterSelect">
                <option value="">Todos os tipos</option>
                <option value="Email">Emails</option>
                <option value="Credential">Credentials</option>
                <option value="API">API Routes</option>
                <option value="Token">Tokens</option>
            </select>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Título</th>
                        <th>Dado Exposto</th>
                        <th>URL do Arquivo JS</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    if [[ -f "$BRID_FILE" && -s "$BRID_FILE" ]]; then
        while IFS= read -r line; do
            local titulo=$(echo "$line" | grep -o '"titulo":"[^"]*"' | cut -d'"' -f4)
            local dado=$(echo "$line" | grep -o '"dado":"[^"]*"' | cut -d'"' -f4)
            local url=$(echo "$line" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
            
            local url_display
            if [[ "$url" == http* ]]; then
                url_display="<a href=\"$url\" target=\"_blank\" class=\"link-btn\">Abrir JS</a>"
            else
                url_display="<code>$url</code>"
            fi
            
            cat >> "${DASHBOARD_DIR}/brid-craftjs.html" <<EOFROW
                    <tr>
                        <td><strong>$titulo</strong></td>
                        <td><code style="color: #fca5a5;">$dado</code></td>
                        <td>$url_display</td>
                    </tr>
EOFROW
        done < "$BRID_FILE"
    fi
    
    cat >> "${DASHBOARD_DIR}/brid-craftjs.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Gerar urls.html
generate_urls_html() {
    local count=$(wc -l < "$VALIDATED_URLS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${DASHBOARD_DIR}/urls.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URLs - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
    <style>
        .status-2xx { background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 0.3rem 0.6rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; }
        .status-3xx { background: linear-gradient(135deg, #f59e0b, #d97706); color: white; padding: 0.3rem 0.6rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; }
        .status-4xx { background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; padding: 0.3rem 0.6rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; }
        .status-5xx { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; padding: 0.3rem 0.6rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; }
        .status-unknown { background: linear-gradient(135deg, #64748b, #475569); color: white; padding: 0.3rem 0.6rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; }
    </style>
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/urls.html"
    
    cat >> "${DASHBOARD_DIR}/urls.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>🔗 URLs</h2>
            <p>Total: <strong id="visibleCount">$count</strong> URLs</p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar URLs...">
            <select id="filterSelect">
                <option value="">Todos os Status</option>
                <option value="status-2xx">2xx - Sucesso</option>
                <option value="status-3xx">3xx - Redirecionamento</option>
                <option value="status-4xx">4xx - Erro Cliente</option>
                <option value="status-5xx">5xx - Erro Servidor</option>
            </select>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Status HTTP</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    local index=1
    if [[ -f "$VALIDATED_URLS_FILE" && -s "$VALIDATED_URLS_FILE" ]]; then
        while IFS= read -r line; do
            local url=$(echo "$line" | grep -oP '"url":"[^"]*"' | cut -d'"' -f4)
            local status=$(echo "$line" | grep -oP '"status":[0-9]+' | cut -d':' -f2)
            
            local status_class="status-unknown"
            local status_text="N/A"
            if [[ "$status" == "0" ]]; then
                status_class="status-unknown"
                status_text="N/A"
            elif [[ "$status" =~ ^2 ]]; then
                status_class="status-2xx"
                status_text="$status"
            elif [[ "$status" =~ ^3 ]]; then
                status_class="status-3xx"
                status_text="$status"
            elif [[ "$status" =~ ^4 ]]; then
                status_class="status-4xx"
                status_text="$status"
            elif [[ "$status" =~ ^5 ]]; then
                status_class="status-5xx"
                status_text="$status"
            fi
            
            cat >> "${DASHBOARD_DIR}/urls.html" <<EOFROW
                    <tr>
                        <td>$index</td>
                        <td><span class="$status_class">$status_text</span></td>
                        <td><a href="$url" target="_blank" style="color: #60a5fa; text-decoration: none; word-break: break-all;">$url</a></td>
                    </tr>
EOFROW
            index=$((index + 1))
        done < "$VALIDATED_URLS_FILE"
    fi
    
    cat >> "${DASHBOARD_DIR}/urls.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Gerar amass.html
generate_amass_html() {
    local count=$(wc -l < "$AMASS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${DASHBOARD_DIR}/amass.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMASS - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/amass.html"
    
    cat >> "${DASHBOARD_DIR}/amass.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>🔍 AMASS - Relações DNS</h2>
            <p>Dados brutos do AMASS (excluindo aaaa_record) - Total: <strong id="visibleCount">$count</strong></p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar...">
            <select id="filterSelect">
                <option value="">Todos os tipos</option>
                <option value="a_record">A Record</option>
                <option value="cname_record">CNAME Record</option>
                <option value="ns_record">NS Record</option>
                <option value="mx_record">MX Record</option>
            </select>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Record Type</th>
                        <th>Destination</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    if [[ -f "$AMASS_FILE" && -s "$AMASS_FILE" ]]; then
        while IFS= read -r line; do
            local source=$(echo "$line" | grep -o '"source":"[^"]*"' | cut -d'"' -f4 | sed 's/ (FQDN)//g')
            local type=$(echo "$line" | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
            local dest=$(echo "$line" | grep -o '"dest":"[^"]*"' | cut -d'"' -f4 | sed 's/ (FQDN)//g; s/ (IPAddress)//g')
            
            local source_display
            if [[ "$source" == *"."* && "$source" != *"/"* ]]; then
                source_display="<a href=\"https://$source\" target=\"_blank\" style=\"color: #60a5fa;\"><code>$source</code></a>"
            else
                source_display="<code>$source</code>"
            fi
            
            cat >> "${DASHBOARD_DIR}/amass.html" <<EOFROW
                    <tr>
                        <td>$source_display</td>
                        <td><span class="severity-info">$type</span></td>
                        <td><code>$dest</code></td>
                    </tr>
EOFROW
        done < "$AMASS_FILE"
    fi
    
    cat >> "${DASHBOARD_DIR}/amass.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# Gerar fierce.html
generate_fierce_html() {
    local count=$(wc -l < "$FIERCE_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    
    cat > "${DASHBOARD_DIR}/fierce.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fierce - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/fierce.html"
    
    cat >> "${DASHBOARD_DIR}/fierce.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>⚡ Fierce - DNS Scan Results</h2>
            <p>Domínios e IPs encontrados via Fierce - Total: <strong id="visibleCount">$count</strong></p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar...">
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Domínio</th>
                        <th>IPv4</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    if [[ -f "$FIERCE_FILE" && -s "$FIERCE_FILE" ]]; then
        while IFS= read -r line; do
            local domain=$(echo "$line" | grep -o '"domain":"[^"]*"' | cut -d'"' -f4)
            local ip=$(echo "$line" | grep -o '"ip":"[^"]*"' | cut -d'"' -f4)
            local ip_base64=$(echo -n "ip=\"$ip\"" | base64 -w0)
            
            cat >> "${DASHBOARD_DIR}/fierce.html" <<EOFROW
                    <tr>
                        <td><a href="https://$domain" target="_blank" style="color: #60a5fa;"><code>$domain</code></a></td>
                        <td><code>$ip</code></td>
                        <td>
                            <a href="https://www.shodan.io/host/$ip" target="_blank" class="link-btn">Shodan</a>
                            <a href="https://search.censys.io/hosts/$ip" target="_blank" class="link-btn">Censys</a>
                            <a href="https://en.fofa.info/result?qbase64=$ip_base64" target="_blank" class="link-btn">FOFA</a>
                        </td>
                    </tr>
EOFROW
        done < "$FIERCE_FILE"
    fi
    
    cat >> "${DASHBOARD_DIR}/fierce.html" <<'EOFHTML'
                </tbody>
            </table>
        </div>
    </div>
    
    <script src="assets/script.js"></script>
</body>
</html>
EOFHTML
}

# ============================================
# END HTML GENERATORS
# ============================================

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

.stat-card .stat-action {
    color: var(--primary);
    font-size: 0.8rem;
    margin-top: 0.75rem;
    opacity: 0;
    transition: all 0.3s ease;
}

.stat-card-link {
    text-decoration: none;
    color: inherit;
    display: block;
}

.stat-card-link:hover .stat-action {
    opacity: 1;
}

.stat-card-link:hover .stat-card {
    transform: translateY(-4px) scale(1.02);
    box-shadow: 0 10px 30px rgba(99, 102, 241, 0.3);
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
