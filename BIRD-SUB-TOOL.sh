#!/bin/bash

echo 'TAKING A LOOK ON SUBDOMAINS'
echo " "
SUBDOMINIO="subdomains.txt"

while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA assetfinder"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-assetfinder.sh $sublinha
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA subfinder"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-subfinder.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA sublist3r"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-sublist3r.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA dnsenum"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-dnsenum.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA dnsrecon"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-dnsrecon.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA fierce"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-fierce.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA amass"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-amass.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA nikto"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-nikto.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA wapiti"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-wapiti.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA nuclei"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-nuclei.sh $sublinha 2>/dev/null
    echo "ANALISANDO O DOMINIO $sublinha COM A FERRAMENTA hakrawler"
    echo " "
done < "$SUBDOMINIO"
while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    sh tool-hakrawler.sh $sublinha 2>/dev/null
done < "$SUBDOMINIO"
