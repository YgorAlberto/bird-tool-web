#!/bin/bash

echo 'TAKING A LOOK ON SUBDOMAINS'
echo " "
SUBDOMINIO="subdomains.txt"

#!/bin/bash

while IFS= read -r sublinha || [[ -n "$sublinha" ]]; do
    echo "======================================="
    echo "[+] Iniciando análise para: $sublinha"
    echo "======================================="

    for tool in \
        tool-amass.sh \
        tool-assetfinder.sh \
        tool-dnsenum.sh \
        tool-dnsrecon.sh \
        tool-fierce.sh \
        tool-hakrawler.sh \
        tool-nikto.sh \
        tool-nuclei.sh \
        tool-subfinder.sh \
        tool-sublist3r.sh \
        tool-wapiti.sh
    do
        echo "[+] Iniciando ${tool} para: $sublinha"
        sh "$tool" "$sublinha" 2>/dev/null
        echo "[✓] Finalizado ${tool} para: $sublinha"
        echo ""
    done

    echo "======================================="
    echo "[✓] Análise completa para: $sublinha"
    echo "======================================="
    echo ""
done < "$SUBDOMINIO"

