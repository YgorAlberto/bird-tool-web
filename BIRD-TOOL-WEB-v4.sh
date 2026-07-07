#!/bin/bash

clear

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║                 BIRD TOOL WEB                       ║"
echo "║            Pentest Automation Suite                ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "██████╗ ██╗██████╗ ██████╗ "
echo "██╔══██╗██║██╔══██╗██╔══██╗"
echo "██████╔╝██║██████╔╝██║  ██║"
echo "██╔══██╗██║██╔══██╗██║  ██║"
echo "██████╔╝██║██║  ██║██████╔╝"
echo "╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ "
echo ""
echo "┌────────────────────────────────────────────────────┐"
echo "│  Ferramentas Integradas:                           │"
echo "│  • assetfinder • hakrawler   • gau                 │"
echo "│  • sublist3r   • urlfinder   • katana              │"
echo "│  • dnsenum    • subfinder    • waybackurls         │"
echo "│  • dnsrecon   • fierce      • bird-craftjs         │"
echo "├────────────────────────────────────────────────────┤"
echo "│  Relatório:                                         │"
echo "│  • 📊 W-BRID + análise IA opcional em segundo plano │"
echo "└────────────────────────────────────────────────────┘"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  👨‍💻 Desenvolvedor: KidMan"
echo "  📁 GitHub: https://github.com/YgorAlberto"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ============================================
# DEPENDÊNCIAS — escolha interativa
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 DEPENDÊNCIAS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
read -p "Deseja instalar/atualizar dependências? [s/N]: " install_deps
if [[ "$install_deps" =~ ^[sS]$ ]]; then
    echo ""
    echo "🔧 Executando instalação de dependências..."
    ./dependencias.sh
    echo ""
    echo "✅ Dependências instaladas"
else
    echo "⏭️  Pulando instalação de dependências"
fi
echo ""

# ============================================
# ESCOPO ATUAL
# ============================================
BIRD_SCOPE_DOMAIN=$(head -n 1 target.txt | sed -E 's#^https?://##;s#/.*$##;s/:.*$//' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
if [[ -z "$BIRD_SCOPE_DOMAIN" ]]; then
    echo "❌ Nenhum domínio válido foi informado em target.txt"
    exit 1
fi
export BIRD_SCOPE_DOMAIN
mkdir -p "OUT-WEB-BIRD/$BIRD_SCOPE_DOMAIN"
echo "$BIRD_SCOPE_DOMAIN" > OUT-WEB-BIRD/.current-scope

# ============================================
# IA — escolha interativa
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🤖 ANÁLISE IA OPCIONAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
read -p "Ativar análise IA em segundo plano após o relatório? [s/N]: " enable_ai
if [[ "$enable_ai" =~ ^[sS]$ ]]; then
    export BIRD_AI_ENABLED=1
else
    export BIRD_AI_ENABLED=0
fi
echo ""

# ============================================
# FERRAMENTAS — Primeira execução (descoberta)
# ============================================

# Ferramentas de descoberta de subdomínios + DNS
discovery_scripts=(
    "./tool-assetfinder.sh"
    "./tool-sublist3r.sh"
    "./tool-subfinder.sh"
)

# Ferramentas secundárias (fierce, hakrawler, waybackurl, gau)
# Estas não buscam subdomínios — usam os já descobertos
secondary_scripts=(
    "./tool-urlfinder.sh"
    "./tool-dnsrecon.sh"
    "./tool-dnsenum.sh"
    "./tool-fierce.sh"
    "./tool-hakrawler.sh"
    "./tool-waybackurl.sh"
    "./tool-gau.sh"
)

# Função para executar uma lista de scripts em paralelo
run_scripts_parallel() {
    local scripts_to_run=("$@")
    local pids=()
    for script in "${scripts_to_run[@]}"; do
        $script &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait $pid
    done
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 INICIANDO BUSCAS COM AS FERRAMENTAS"
echo "📅 $(date '+%d/%m/%Y %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
# Primeira execução: descoberta de subdomínios + DNS + URLs
run_scripts_parallel "${discovery_scripts[@]}" "${secondary_scripts[@]}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ KATANA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-katana.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💾 SALVANDO SUBDOMÍNIOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./parsing-domains.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ VALIDANDO SUBDOMÍNIOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./domain-validator.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 ESCANEANDO SUBDOMÍNIOS ENCONTRADOS"
echo "   (fierce, hakrawler, waybackurl, gau)"
echo "📅 $(date '+%d/%m/%Y %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
# Segunda execução: apenas ferramentas secundárias nos subs descobertos
run_scripts_parallel "${secondary_scripts[@]}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ KATANA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-katana.sh

echo " "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 ANALISANDO ARQUIVOS EM BUSCA DE TERMOS INTERESSANTES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-bird-craftjs.sh

echo " "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔎 CONSOLIDANDO ACHADOS HTTP, TLS, HEADERS E MÉTODOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-bird-final-findings.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ FERRAMENTAS FINALIZADAS"
echo "📊 GERANDO DASHBOARD HTML"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📊 Gerando relatório W-BRID..."
./tool-web-dashboard.sh

if [[ "$BIRD_AI_ENABLED" == "1" ]]; then
    echo "🤖 Iniciando análise IA em segundo plano..."
    nohup ./tool-web-ai-analysis.sh > "OUT-WEB-BIRD/$BIRD_SCOPE_DOMAIN/$BIRD_SCOPE_DOMAIN-bird-ai.log" 2>&1 &
    echo "🤖 PID da análise IA: $!"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                    BIRD TOOL WEB - FINALIZADO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📅 Data/Hora: $(date '+%d/%m/%Y %H:%M:%S')"
echo "📁 Resultados salvos em: OUT-WEB-BIRD/"
echo "📁 Relatório salvo em: dashboard/"
[[ "$BIRD_AI_ENABLED" == "1" ]] && echo "🤖 A análise IA continuará em segundo plano; atualize a página para liberar o menu quando concluir."

echo ""
echo "🌐 Abrindo dashboard no navegador..."
xdg-open "dashboard/index.html" 2>/dev/null &
