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
echo "│  • amass      • nuclei       • hakrawler           │"
echo "│  • assetfinder • sublist3r   • urlfinder           │"
echo "│  • dnsenum    • subfinder    • waybackurls         │"
echo "│  • dnsrecon   • wapiti       • bird-craftjs        │"
echo "│  • fierce     • nikto                              │"
echo "└────────────────────────────────────────────────────┘"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  👨‍💻 Desenvolvedor: KidMan"
echo "  📁 GitHub: https://github.com/YgorAlberto"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "⚠️   ATENÇÃO: Verifique as dependências antes de continuar"
echo ""
echo "📋 Fluxo de Execução:"
echo "   1. Coleta de Subdomínios (Assetfinder → Sublist3r → Subfinder)"
echo "   2. Análise DNS (DNSenum → Amass → DNSrecon → Fierce)"
echo "   3. Scanner de Vulnerabilidades (Nikto → Wapiti → Nuclei)"
echo "   4. Coleta de URLs (Hakrawler → URLfinder → Waybackurls)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🕐 Início: $(date)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
read -p "Pressione ENTER para verificar dependências..."
echo ""
echo "🔍 Executando verificação de dependências..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
./dependencias.sh

# Lista de scripts para a primeira execução
scripts=(
    "./tool-assetfinder.sh"
    "./tool-sublist3r.sh"
    "./tool-subfinder.sh"
    "./tool-dnsenum.sh"
    "./tool-amass.sh"
    "./tool-dnsrecon.sh"
    "./tool-fierce.sh"
    "./tool-nikto.sh"
    "./tool-wapiti.sh"
    "./tool-nuclei.sh"
    "./tool-hakrawler.sh"
)

# Função para executar uma lista de scripts em paralelo
run_parallel() {
    local pids=()
    # Inicia todos os scripts em segundo plano
    for script in "${scripts[@]}"; do
        $script &
        pids+=($!)
    done

    # Espera cada processo terminar
    for pid in "${pids[@]}"; do
        wait $pid
    done
}

# Primeira execução em paralelo
run_parallel

echo " "
echo " "
echo "LOOKING AROUND FOR URLS"
echo " "
echo " "
./tool-urlfinder.sh
./tool-waybackurl.sh
echo " "
echo " "
echo "LOOKING FOR INTERESTING TERMS"
echo " "
echo " "
./tool-bird-craftjs.sh
echo "CRAFT JS TERMINADO"
echo ""

echo " DONE "
date
echo " "
echo "SAVING SUBDOMAINS FOUND"
./parsing-domains.sh
echo " "
date
echo "VALIDATING SUBDOMAINS FOUND"
echo " "
#FAZ A VALIDAÇÃO DE CADA SUBDOMINIO ENCONTRADO
./domain-validator.sh
echo " DONE "
date
echo " "
echo " VARRENDO OS SUBDOMAINS ENCONTRADOS "
#RODA AS FERRAMENTAS NOVAMENTE NOS SUBDOMINIOS ENCONTRADO

# Segunda execução em paralelo
run_parallel

#Roda o final para fazer o dashboard com as informações organizadas
./bird-analyzer.sh

echo " "
date
echo " "
