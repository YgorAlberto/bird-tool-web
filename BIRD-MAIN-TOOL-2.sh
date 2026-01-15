#!/bin/bash

echo " "
echo "BIRD TOOL WEB"
echo "FERRAMENTA PARA ANÁLISE WEB COM AS SEGUINTES FERRAMENTAS INTEGRADAS"
echo "amass assetfinder dnsenum dnsrecon fierce hakrawler nikto nuclei subfinder sublist3r wapiti"
echo "By KidMan - git: https://github.com/YgorAlberto"
echo " "
echo " "
echo " "
echo "ATENÇÃO VERIFIQUE SE TODAS AS FERRAMENTAS ESTÃO INSTALADAS E CONTINUE"
echo " "
echo "TAKING A LOOK ON DOMAINS"
echo " "
date
echo " "
echo "essa ferramenta executa em linha: ASSETFINDER -> SUBLIST3R -> SUBFINDER -> DNENUM -> AMASS -> DNSRECON -> FIERCE -> NIKTO -> WAPITI -> NUCLEI -> HAKRAWLER -> URLFINDER -> WAYBACKURLS -> BIRD-CRAFTJS"

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
./bird-craftjs-v2.py
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

echo " "
date
echo " "
