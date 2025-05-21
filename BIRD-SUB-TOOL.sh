#!/bin/bash

#echo 'TAKING A LOOK ON SUBDOMAINS'
#echo " "
#SUBDOMINIO="subdomains.txt"

#./tool-assetfinder.sh

#for sub in $(cat subdomains.txt);do ./tool-assetfinder.sh $sub && ./tool-sublist3r.sh $sub && ./tool-subfinder.sh $sub && ./tool-dnsenum.sh $sub && ./tool-dnsrecon.sh $sub && ./tool-fierce.sh $sub && ./tool-amass.sh $sub && ./tool-nikto.sh $sub && ./tool-wapiti.sh $sub && ./tool-nuclei.sh $sub && ./tool-hakrawler.sh $sub ;done

#while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
#    echo "======================================="
#    echo "[+] Iniciando análise para: $sublinha"
#    echo "======================================="
#
#    for tool in \
#        tool-amass.sh \
#        tool-assetfinder.sh \
#        tool-dnsenum.sh \
#        tool-dnsrecon.sh \
#        tool-fierce.sh \
#        tool-hakrawler.sh \
#        tool-nikto.sh \
#        tool-nuclei.sh \
#        tool-subfinder.sh \
#        tool-sublist3r.sh \
#        tool-wapiti.sh
#    do
#        echo "[+] Iniciando ${tool} para: $sublinha"
#        sh "$tool" "$sublinha" 2>/dev/null
#        echo "[✓] Finalizado ${tool} para: $sublinha"
#        echo ""
#    done
#
#    echo "======================================="
#    echo "[✓] Análise completa para: $sublinha"
#    echo "======================================="
#    echo ""
#done < "$SUBDOMINIO"

