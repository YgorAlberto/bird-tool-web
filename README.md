# W-BRID — Bird Tool Web

Suíte de reconhecimento e análise de segurança web para escopos autorizados. O W-BRID executa descoberta de subdomínios, coleta de URLs, crawling, validação, análise de JavaScript, checagens HTTP/TLS/headers/métodos e consolida tudo em um relatório HTML único.

O relatório normal é gerado primeiro. A análise IA é opcional, roda em segundo plano e atualiza o menu `IA Findings` quando termina.

## Modelo de escopo

O domínio analisado é sempre lido de `target.txt` no início da execução.

```bash
echo "dominio-autorizado.example" > target.txt
./BIRD-TOOL-WEB-v4.sh
```

O script normaliza o domínio, grava o escopo atual em `OUT-WEB-BIRD/.current-scope` e usa esse valor para filtrar o relatório e a IA. Nada deve ficar fixo nos scripts: cada execução deve refletir somente o domínio corrente e seus subdomínios.

## Instalação

```bash
chmod +x *.sh
./dependencias.sh
```

O script principal também pergunta, de forma interativa, se você deseja instalar ou atualizar dependências antes da execução.

## Fluxo de execução

```text
Descoberta inicial
  → Katana
  → parsing dos domínios
  → validação dos subdomínios
  → segunda rodada das ferramentas principais
  → Katana novamente
  → Bird-CraftJS
  → Bird Final Findings
  → relatório W-BRID
  → IA opcional em segundo plano
```

O Katana roda duas vezes: uma após a primeira fase de descoberta e outra depois da validação/segunda rodada das ferramentas.

## Script principal

```bash
./BIRD-TOOL-WEB-v4.sh
```

Durante a execução, o script pergunta:

- se deve instalar/atualizar dependências;
- se deve ativar a análise IA em segundo plano após o relatório normal.

Quando a IA é ativada, o relatório HTML já fica pronto antes dela terminar. Depois que a IA concluir, basta atualizar a página para liberar e preencher o menu `IA Findings`.

## Saídas principais

```text
OUT-WEB-BIRD/<target>/
  <target>-FULL-URLs
  <target>-bird-craftjs
  <target>-bird-craftjs.json
  <target>-bird-final-findings.json
  <target>-bird-ai-findings.json
  <target>-bird-ai-manifest.json
  <target>-bird-ai.log
  demais outputs das ferramentas

dashboard/
  index.html
  relatorio.html
  subdomains.html
  brid-craftjs.html
  ai-findings.html
  final-findings.html
  urls.html
  tree.html
  dns.html
  assets/
```

`dashboard/index.html` e `dashboard/relatorio.html` apontam para a visão principal do relatório.

## Relatório HTML

O título da página e o cabeçalho exibem dinamicamente:

```text
W-BRID - DOMÍNIO
```

A ordem dos menus é:

1. Dashboard
2. Subdomínio
3. Bird-Craft
4. IA Findings
5. Final Findings
6. Urls
7. Tree
8. DNS

### Dashboard

A página inicial fica limpa e focada em visão executiva do escopo:

- subdomínios ativos;
- subdomínios inativos;
- IPs únicos;
- URLs coletadas;
- gráfico com as portas mais recorrentes, quando houver dados.

### Subdomínio

Lista subdomínios, status, IPs, portas, serviços e ações úteis. Quando a IA termina, a coluna `Infraestrutura IA` passa a mostrar informações como CDN, WAF, cloud, provider e ASN/IP quando detectados.

### Bird-Craft

Mostra endpoints e achados extraídos de HTML/JavaScript. Campos muito longos quebram linha no próprio card/tabela para evitar rolagem horizontal e facilitar acesso aos links de referência.

### IA Findings

Menu complementar. Enquanto a IA está rodando, o menu fica em estado de espera. Ao concluir, a página exibe:

- infraestrutura detectada;
- tecnologias e versões;
- endpoints de API;
- achados relevantes e confirmáveis;
- fontes exatas onde cada evidência foi encontrada.

Links longos e referências usam contraste alto e quebra de linha para leitura mais confortável.

### Final Findings

Integra no relatório principal os achados HTTP/TLS/headers/métodos gerados pelo `bird-final-findings.py`, agrupando comportamentos importantes sem repetir listas gigantes de URLs.

## Bird-CraftJS

O wrapper permanece simples e em linha única:

```bash
./tool-bird-craftjs.sh
```

Ele consolida as URLs em `OUT-WEB-BIRD/<target>/<target>-FULL-URLs` e grava:

```text
OUT-WEB-BIRD/<target>/<target>-bird-craftjs
OUT-WEB-BIRD/<target>/<target>-bird-craftjs.json
```

A ferramenta operacional é:

```text
tool-bird-craftjs-v2.py
```

A versão anterior permanece no diretório como:

```text
tool-bird-craftjs-legacy.py
```

Isso permite comparar outputs antigos e novos sem precisar alterar os demais scripts que já chamavam o nome antigo.

O scanner:

- respeita o domínio raiz autorizado e subdomínios;
- bloqueia entradas externas e redirecionamentos fora de escopo;
- ignora imagens, CSS, fontes, mídia e respostas sem valor técnico;
- analisa HTML, JavaScript, chunks e source maps;
- extrai endpoints, métodos, parâmetros, auth, chaves e padrões sensíveis;
- reduz falsos positivos de segredo usando contexto, formato e entropia;
- grava TXT e JSON para consumo do dashboard.

## Bird Final Findings

O wrapper padrão é:

```bash
./tool-bird-final-findings.sh
```

Uso direto:

```bash
python3 bird-final-findings.py -f urls.txt \
  --scope-domain dominio-autorizado.example \
  --json-output findings.json
```

Por padrão, ele gera JSON estruturado para o dashboard principal. O dashboard HTML autocontido antigo só é gerado quando solicitado:

```bash
python3 bird-final-findings.py -f urls.txt \
  --scope-domain dominio-autorizado.example \
  --json-output findings.json \
  --dashboard-html
```

Principais verificações:

- headers de segurança ausentes ou fracos;
- CORS;
- cookies;
- TLS e redirecionamento;
- arquivos sensíveis comuns;
- diferenças entre métodos HTTP;
- ASN/provider, quando disponível;
- evidências agrupadas por causa raiz.

Por padrão, são testados `GET`, `HEAD`, `OPTIONS`, `POST` com payload canário inválido e `TRACE`. Métodos mais sensíveis podem ser ativados somente com autorização explícita:

```bash
--full-http-methods
```

Essa flag inclui métodos como `PUT`, `PATCH`, `DELETE`, `CONNECT` e `PROPFIND` com payload canário.

## Análise IA

A IA usa Ollama local e é executada pelo wrapper:

```bash
./tool-web-ai-analysis.sh
```

No fluxo normal, ela só começa depois que o relatório principal já foi gerado.

### Comportamento esperado

A IA:

- lê os arquivos textuais úteis dentro de `OUT-WEB-BIRD/<target>/`;
- ignora imagens, CSS, fontes, mídia e binários;
- reanalisa URLs, subdomínios, IPs e links dentro do escopo autorizado;
- baixa e analisa apenas JavaScript pertencente ao domínio raiz e subdomínios;
- processa `robots.txt`, `sitemap.xml` e índices de sitemap;
- procura endpoints de API, rotas, métodos, parâmetros e autenticação;
- procura chaves, tokens, senhas, regras de negócio e padrões sensíveis com contexto;
- faz fuzzing de leitura em páginas administrativas, login, docs de API, Swagger/OpenAPI, GraphQL, debug, health, métricas, painéis e arquivos sensíveis;
- identifica tecnologias, versões, WAF, CDN, cloud/provider e ASN;
- verifica AXFR, indícios de subdomain takeover e buckets públicos AWS/GCP derivados de nomes do escopo;
- executa probes controlados para path traversal, reflexão XSS e SSRF com canário local não sensível;
- remove achados baseados em HTTP 404, páginas editoriais/blog e conteúdo sem impacto prático;
- reporta somente achados relevantes e confirmáveis.

O inventário de endpoints de API aparece separado dos achados. Ele mostra método, endpoint completo e as fontes exatas onde o endpoint foi encontrado.

### Ollama e limites

Variáveis úteis:

```bash
export BIRD_AI_MODEL="deepseek-r1:14b"
export BIRD_AI_MAX_CALLS="6"
export OLLAMA_BASE_URL="http://localhost:11434"
export SHODAN_API_KEY="sua-chave"
```

Exemplo de execução manual com limites:

```bash
./tool-web-ai-analysis.sh \
  --llm-max-calls 6 \
  --page-limit 1500 \
  --active-web-limit 400 \
  --fuzz-limit 100 \
  --bucket-limit 50 \
  --rdap-limit 80 \
  --sitemap-limit 60 \
  --sitemap-url-limit 50000
```

Parâmetros importantes:

- `--llm-max-calls`: limita quantos lotes semânticos serão enviados ao Ollama;
- `--page-limit`: limita páginas priorizadas para nova requisição HTTP;
- `--active-web-limit`: limita probes ativos de parâmetros;
- `--fuzz-limit`: limita fuzzing de caminhos;
- `--bucket-limit`: limita nomes testados em buckets AWS/GCP;
- `--rdap-limit`: limita enriquecimento RDAP de IPs;
- `--sitemap-limit`: limita documentos sitemap processados;
- `--sitemap-url-limit`: limita URLs incorporadas a partir de sitemaps.

Para acelerar bastante a IA em máquinas menores:

```bash
./tool-web-ai-analysis.sh \
  --llm-max-calls 2 \
  --page-limit 500 \
  --active-web-limit 100 \
  --fuzz-limit 40 \
  --bucket-limit 20 \
  --rdap-limit 30
```

Também é possível desativar partes ativas:

```bash
./tool-web-ai-analysis.sh --active-web-limit 0 --bucket-limit 0
```

Mesmo com limites menores, a extração determinística dos arquivos textuais úteis permanece ativa.

## Regenerar somente o relatório

Se os outputs já existem e você quer apenas reconstruir o HTML:

```bash
./tool-web-dashboard.sh
```

Se a IA já terminou, os arquivos `dashboard/assets/ai-data.js` e `dashboard/assets/ai-status.js` alimentam o menu `IA Findings`.

## Boas práticas de execução

- Use um domínio por execução em `target.txt`.
- Apague ou arquive outputs antigos quando quiser uma rodada completamente limpa.
- Ajuste os limites da IA conforme o tamanho do escopo.
- Use `--full-http-methods` somente quando houver autorização explícita para métodos potencialmente sensíveis.
- Revise o log da IA em `OUT-WEB-BIRD/<target>/<target>-bird-ai.log` quando o menu demorar a ser liberado.

## Aviso

Use somente em sistemas, domínios e redes para os quais exista autorização explícita. Métodos ativos, fuzzing, crawling e validações de exposição podem gerar carga e devem respeitar as regras do teste.
