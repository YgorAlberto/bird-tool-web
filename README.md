# 🐦 BIRD TOOL WEB

**BIRD TOOL WEB** é uma ferramenta de automação para análise de segurança em aplicações web e reconhecimento de subdomínios, integrando diversas ferramentas de análise em um único script.

## 📌 Objetivo

Automatizar a análise inicial de um domínio e seus subdomínios, utilizando ferramentas amplamente reconhecidas na área de segurança ofensiva. O fluxo da ferramenta é:

1. Executa uma varredura no domínio alvo com múltiplas ferramentas.
2. Coleta subdomínios encontrados durante a varredura inicial.
3. Filtra os subdomínios válidos.
4. Executa novamente todas as ferramentas em cada subdomínio encontrado.

---

## ⚙️ Ferramentas Integradas

O script executa automaticamente as seguintes ferramentas durante a análise:

- [`amass`](https://github.com/owasp-amass/amass) — Reconhecimento e enumeração de subdomínios.
- [`assetfinder`](https://github.com/tomnomnom/assetfinder) — Descoberta de subdomínios e ativos.
- [`dnsenum`](https://github.com/fwaeytens/dnsenum) — Enumeração DNS.
- [`dnsrecon`](https://github.com/darkoperator/dnsrecon) — Reconhecimento e enumeração de registros DNS.
- [`fierce`](https://github.com/mschwager/fierce) — Ferramenta para mapeamento DNS.
- [`hakrawler`](https://github.com/hakluke/hakrawler) — Rastreio de URLs em aplicações web.
- [`nikto`](https://github.com/sullo/nikto) — Scanner de vulnerabilidades em servidores web.
- [`nuclei`](https://github.com/projectdiscovery/nuclei) — Scanner de vulnerabilidades baseado em templates.
- [`subfinder`](https://github.com/projectdiscovery/subfinder) — Enumeração rápida de subdomínios.
- [`sublist3r`](https://github.com/aboul3la/Sublist3r) — Ferramenta para descoberta de subdomínios.
- [`wapiti`](https://github.com/wapiti-scanner/wapiti) — Scanner de vulnerabilidades em aplicações web.

---

## 🚀 Como Funciona

1. **Entrada:** Um domínio alvo.
2. **Análise Inicial:** Todas as ferramentas são executadas no domínio principal.
3. **Descoberta de Subdomínios:** As ferramentas listadas capturam subdomínios.
4. **Validação de Subdomínios:** Apenas os subdomínios válidos são mantidos.
5. **Reanálise:** As ferramentas são executadas novamente, agora em cada subdomínio válido.

---

## 📦 Pré-requisitos

- Linux (recomendado: Kali Linux)
- Ferramentas listadas instaladas no sistema e disponíveis no PATH

### Instalação das ferramentas (exemplo com `apt` e `go install`):

```bash
sudo apt install amass dnsenum dnsrecon fierce nikto wapiti
sudo apt install golang-go
sudo apt install assetfinder
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### COMO UTILIZAR

```bash
git clone https://github.com/YgorAlberto/bird-tool-web.git
chmod +x *.sh
echo "seu.alvo.com.br" > target.txt
./BIRD-MAIN-TOOL.sh
