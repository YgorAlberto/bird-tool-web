sudo apt update
sudo apt install -y assetfinder dnsenum dnsrecon fierce hakrawler subfinder sublist3r 
sudo apt install -y golang-go python3 python3-pip jq curl
python3 -m pip install --user requests beautifulsoup4 lxml colorama dnspython cryptography Pillow ipwhois playwright
go install github.com/tomnomnom/waybackurls@latest
sudo mv $(go env GOPATH)/bin/waybackurls /usr/local/bin/
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
sudo mv $(go env GOPATH)/bin/urlfinder /usr/local/bin/
go install github.com/lc/gau/v2/cmd/gau@latest
sudo mv $(go env GOPATH)/bin/gau /usr/local/bin/
go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo mv $(go env GOPATH)/bin/katana /usr/local/bin/

# ============================================
# Análise IA opcional - Ollama + Modelo
# ============================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🤖 Instalando Ollama (LLM para Dashboard IA)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -fsSL https://ollama.ai/install.sh | sh
echo ""
echo "📦 Baixando modelo deepseek-r1:14b..."
ollama pull deepseek-r1:14b
echo ""
echo "✅ Ollama + deepseek-r1:14b instalados com sucesso"
