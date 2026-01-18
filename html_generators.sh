#!/bin/bash
# Funções auxiliares para gerar páginas HTML adicionais

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
    
    # Processar cada linha de vulnerabilidade
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
                <option value="Subdomain">Subdomains</option>
                <option value="IPv4">IPv4</option>
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
    
    # Processar BRID-CRAFTJS findings
    if [[ -f "$BRID_FILE" && -s "$BRID_FILE" ]]; then
        while IFS= read -r line; do
            local titulo=$(echo "$line" | grep -o '"titulo":"[^"]*"' | cut -d'"' -f4)
            local dado=$(echo "$line" | grep -o '"dado":"[^"]*"' | cut -d'"' -f4)
            local url=$(echo "$line" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
            
            # Formatar URL para link se começar com http
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
    local urls=$(sort -u "$URLS_FILE" 2>/dev/null | grep -v '^$')
    local count=$(echo "$urls" | grep -v '^$' | wc -l | tr -d ' ')
    
    cat > "${DASHBOARD_DIR}/urls.html" <<'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URLs - Bird Tool Web Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
EOFHTML

    generate_nav >> "${DASHBOARD_DIR}/urls.html"
    
    cat >> "${DASHBOARD_DIR}/urls.html" <<EOFHTML
    
    <div class="container">
        <div class="card">
            <h2>🔗 URLs Descobertas</h2>
            <p>Total: <strong id="visibleCount">$count</strong> URLs únicas</p>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Buscar URLs...">
            <select id="filterSelect">
                <option value="">Todos os tipos</option>
                <option value=".js">.js - JavaScript</option>
                <option value=".css">.css - CSS</option>
                <option value=".json">.json - JSON</option>
                <option value=".xml">.xml - XML</option>
                <option value="api">API</option>
            </select>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
EOFHTML
    
    local index=1
    echo "$urls" | grep -v '^$' | while read -r url; do
        cat >> "${DASHBOARD_DIR}/urls.html" <<EOFROW
                    <tr>
                        <td>$index</td>
                        <td><a href="$url" target="_blank" style="color: #60a5fa; text-decoration: none; word-break: break-all;">$url</a></td>
                    </tr>
EOFROW
        index=$((index + 1))
    done
    
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
    
    # Processar AMASS data
    if [[ -f "$AMASS_FILE" && -s "$AMASS_FILE" ]]; then
        while IFS= read -r line; do
            local source=$(echo "$line" | grep -o '"source":"[^"]*"' | cut -d'"' -f4 | sed 's/ (FQDN)//g')
            local type=$(echo "$line" | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
            local dest=$(echo "$line" | grep -o '"dest":"[^"]*"' | cut -d'"' -f4 | sed 's/ (FQDN)//g; s/ (IPAddress)//g')
            
            # Verificar se source é domínio para criar link
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
            <p>Domínios e IPs encontrados via Fierce (filtrado por escopo) - Total: <strong id="visibleCount">$count</strong></p>
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
    
    # Processar Fierce data
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
