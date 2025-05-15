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

if [ -z "$1" ]; then
    echo "Erro: DOMINIO não informado."
    echo "Uso: BIRD-MAIN-TOOL.sh domain"
    exit 1
fi

# FERRAMENTA PRINCIPAL QUE FAZ A ANÁLISE DOS DOMINIOS NA LISTA
DOMINIO=$1

echo "TAKING A LOOK ON DOMAINS"
echo " "
date
echo " "
while IFS= read -r linha || [[ -n "$linha" ]]; do
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA assetfinder..."
    echo " "
    sh tool-assetfinder.sh $linha 
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA sublist3r..."
    echo " "
    sh tool-sublist3r.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA subfinder..."
    echo " "
    sh tool-subfinder.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA dnsenum..."
    echo " "
    sh tool-dnsenum.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA amass..."
    echo " "
    sh tool-amass.sh $linha 2>/dev/null
    echo "CAPTURANDO SUBDOMINIIOS ENCONTRADOS..."
    echo " "
    sh parsing-domains.sh $linha
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA dnsrecon..."
    echo " "
    sh tool-dnsrecon.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA fierce..."
    echo " "
    sh tool-fierce.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA nikto..."
    echo " "
    sh tool-nikto.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA wapiti..."
    echo " "
    sh tool-wapiti.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA nuclei..."
    echo " "
    sh tool-nuclei.sh $linha 2>/dev/null
    echo "ANALISANDO O DOMINIO $linha COM A FERRAMENTA hakrawler..."
    echo " "
    sh tool-hakrawler.sh $linha 2>/dev/null
done < "$DOMINIO"
date
#FAZ A VALIDAÇÃO DE CADA SUBDOMINIO ENCONTRADO
echo "VALIDATING SUBDOMAINS FOUND"
echo " "
sh domain-validator.sh
echo " "
date
echo " "
#RODA AS FERRAMENTAS NOVAMENTE NOS SUBDOMINIOS ENCONTRADO
./BIRD-SUB-TOOL.sh
echo " "
date
echo " "
