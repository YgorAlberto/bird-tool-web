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
echo "essa ferramenta executa em linha: ASSETFINDER -> SUBLIST3R -> SUBFINDER -> DNENUM -> AMASS -> DNSRECON -> FIERCE -> NIKTO -> WAPITI -> NUCLEI -> HAKRAWLER"
./tool-assetfinder.sh
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
./tool-assetfinder.sh
echo " "
date
echo " "
