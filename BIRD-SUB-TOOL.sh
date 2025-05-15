#!/bin/bash

echo 'TAKING A LOOK ON SUBDOMAINS'
echo " "
SUBDOMINIO="subdomains.txt"

while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA assetfinder"
    echo " "
    sh tool-assetfinder.sh $sublinha
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA subfinder"
    echo " "
    sh tool-subfinder.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA sublist3r"
    echo " "
    sh tool-sublist3r.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA dnsenum"
    echo " "
    sh tool-dnsenum.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA dnsrecon"
    echo " "
    sh tool-dnsrecon.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA fierce"
    echo " "
    sh tool-fierce.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA amass"
    echo " "
    sh tool-amass.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA nikto"
    echo " "
    sh tool-nikto.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA wapiti"
    echo " "
    sh tool-wapiti.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA nuclei"
    echo " "
    sh tool-nuclei.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA hakrawler"
    echo " "
    sh tool-hakrawler.sh $sublinha 2>/dev/null
done < "$SUBDOMINIO"
