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

# essa ferramenta executa o ASSETFINDER -> ...
./tool-assetfinder.sh
echo " "
date
echo " "
./parsing-domains.sh
#for domain in $(cat domain);do ./tool-assetfinder.sh $domain && ./tool-sublist3r.sh $domain && ./tool-subfinder.sh $domain && ./tool-dnsenum.sh $domain && ./tool-dnsrecon.sh $domain && ./tool-fierce.sh $domain && ./tool-amass.sh $domain && ./tool-nikto.sh $domain && ./tool-wapiti.sh $domain && ./tool-nuclei.sh $domain && ./tool-hakrawler.sh $domain && ./parsing-domains.sh ;done

#while IFS= read -r linha || [[ -n "$linha" ]]; do
#    echo "======================================="
#    echo "[+] Iniciando análise para: $linha"
#    echo "======================================="
#
#    for tool in \
#        tool-assetfinder.sh \
#        tool-sublist3r.sh \
#        tool-subfinder.sh \
#        tool-dnsenum.sh \
#        tool-amass.sh
#    do
#        echo "[+] Executando ${tool} para: $linha"
#        sh "$tool" "$linha" 2>/dev/null
#        echo "[✓] Finalizado ${tool} para: $linha"
#        echo ""
#    done
#
#    echo "[+] Executando parsing-domains.sh para: $linha"
#    sh parsing-domains.sh "$linha" 2>/dev/null
#    echo "[✓] Finalizado parsing-domains.sh para: $linha"
#    echo ""
#
#    for tool in \
#        tool-dnsrecon.sh \
#        tool-fierce.sh \
#        tool-nikto.sh \
#        tool-wapiti.sh \
#        tool-nuclei.sh \
#        tool-hakrawler.sh
#    do
#        echo "[+] Executando ${tool} para: $linha"
#        sh "$tool" "$linha" 2>/dev/null
#        echo "[✓] Finalizado ${tool} para: $linha"
#        echo ""
#    done
#
#    echo "======================================="
#    echo "[✓] Análise completa para: $linha"
#    echo "======================================="
#    echo ""
#done < "$DOMINIO"

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
