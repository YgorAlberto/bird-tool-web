#!/usr/bin/env python3
"""Análise complementar assíncrona dos outputs do W-BRID usando Ollama local."""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import mimetypes
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    import urllib3
except ImportError:
    print("[ERRO] Instale requests: pip install requests", file=sys.stderr)
    raise SystemExit(2)

try:
    import dns.query
    import dns.resolver
    import dns.zone
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False


VERSION = "1.3.0"
CHUNK_CHARS = 14_000
MAX_RESPONSE_CHARS = 30_000
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".map"}
SKIP_EXTENSIONS = {
    ".css", ".scss", ".sass", ".less", ".png", ".jpg", ".jpeg", ".gif",
    ".webp", ".avif", ".bmp", ".ico", ".svg", ".woff", ".woff2", ".ttf",
    ".eot", ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".pdf", ".zip",
    ".gz", ".tgz", ".7z", ".rar", ".jar", ".war", ".exe", ".dll", ".so",
}
SENSITIVE_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/config.json", "/config.yml", "/config.yaml", "/settings.json", "/appsettings.json",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/database.sql", "/dump.sql",
}
FUZZ_PATHS = [
    "/admin", "/admin/login", "/administrator", "/manage", "/management", "/backoffice",
    "/painel", "/dashboard", "/console", "/cpanel", "/wp-admin", "/user/login", "/login",
    "/phpmyadmin", "/adminer.php", "/jenkins", "/grafana", "/kibana", "/prometheus",
    "/signin", "/auth", "/auth/login", "/sso", "/oauth", "/oauth/callback",
    "/forgot-password", "/reset-password", "/api", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html", "/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi.yml", "/api/openapi.json", "/api/swagger.json",
    "/api-docs", "/api/docs", "/docs", "/redoc", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/api/graphql", "/graphiql", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/configprops", "/actuator/beans", "/actuator/loggers",
    "/health", "/healthz", "/api/health", "/api/status", "/api/system/status", "/metrics", "/server-status", "/phpinfo.php",
    "/debug", "/trace", "/status", "/info", "/version", "/build",
    "/.well-known/openid-configuration", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/sitemap-index.xml", "/sitemap.xml.gz",
] + sorted(SENSITIVE_PATHS)
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
API_MARKERS = ("/api", "/rest", "/graphql", "/gql", "/rpc", "/oauth", "/openid", "/swagger", "/v1/", "/v2/", "/v3/", "/internal/")
INTEREST_MARKERS = (
    "/api", "graphql", "swagger", "openapi", "api-docs", "redoc", "oauth", "openid",
    "login", "signin", "admin", "administrator", "manage", "dashboard", "console", "backoffice",
    "actuator", "metrics", "debug", "server-status", "phpinfo", ".env", ".git", "config", "backup",
    "upload", "download", "webhook", "callback", "internal", "private",
)
EDITORIAL_PATH_MARKERS = ("/blog/", "/news/", "/noticias/", "/article/", "/articles/", "/post/", "/posts/", "/category/", "/tag/")
API_CALL_RE = re.compile(
    r"(?P<call>fetch|axios\.(?P<axios>get|post|put|patch|delete|head|options)|\$\.(?P<jquery>get|post)|open)"
    r"\s*\(\s*[\"'`](?P<url>https?://[^\"'`\s]+|/[^\"'`\s]+|\.\.?/[^\"'`\s]+)",
    re.I,
)
API_PATH_RE = re.compile(
    r"[\"'`](?P<url>(?:https?://[^\"'`\s]+|/[^\"'`\s]*?(?:api|rest|graphql|gql|rpc|oauth|openid|swagger|v[1-9])(?:[/?.#][^\"'`\s]*)?))[\"'`]",
    re.I,
)
HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.I)
XHR_OPEN_RE = re.compile(r"\.open\s*\(\s*[\"'](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\s*,\s*[\"'`](?P<url>[^\"'`\s]+)", re.I)
TRAVERSAL_PARAMETERS = {"file", "filename", "filepath", "path", "page", "template", "include", "folder", "dir", "document", "download", "view"}
SSRF_PARAMETERS = {"url", "uri", "link", "src", "source", "target", "dest", "destination", "redirect", "redirect_uri", "callback", "webhook", "feed", "proxy", "image_url"}
XSS_PARAMETERS = {"q", "query", "search", "s", "term", "keyword", "name", "message", "redirect", "return", "next", "url"}
SIGNAL_RE = re.compile(
    r"(?i)(?:/api\b|graphql|swagger|openapi|oauth|openid|login|signin|admin|dashboard|console|"
    r"password|passwd|secret|token|api[_-]?key|authorization|bearer|cookie|cors|origin|postmessage|"
    r"innerhtml|document\.write|\beval\s*\(|fetch\s*\(|axios|xmlhttprequest|webhook|callback|redirect|"
    r"\.env\b|\.git\b|bucket|amazonaws|storage\.googleapis|ssrf|traversal|include|template|upload|download|"
    r"permission|isadmin|user[_-]?role|feature[_-]?flag|price|discount|quota|rate[_-]?limit)"
)
TAKEOVER_PROVIDERS = {
    "github.io": ("GitHub Pages", "there isn't a github pages site here"),
    "herokudns.com": ("Heroku", "no such app"),
    "herokuapp.com": ("Heroku", "no such app"),
    "s3.amazonaws.com": ("AWS S3", "nosuchbucket"),
    "azurewebsites.net": ("Azure", "404 web site not found"),
    "trafficmanager.net": ("Azure", "the resource you are looking for"),
    "fastly.net": ("Fastly", "fastly error: unknown domain"),
    "netlify.app": ("Netlify", "not found - request id"),
    "vercel.app": ("Vercel", "deployment_not_found"),
    "pantheonsite.io": ("Pantheon", "the gods are wise"),
}
INFRA_CNAME_PROVIDERS = {
    "cloudfront.net": ("AWS CloudFront", "CDN/Cloud"),
    "amazonaws.com": ("AWS", "Cloud"),
    "azurefd.net": ("Azure Front Door", "CDN/Cloud"),
    "azurewebsites.net": ("Azure App Service", "Cloud"),
    "trafficmanager.net": ("Azure Traffic Manager", "Cloud"),
    "googlehosted.com": ("Google Cloud", "Cloud"),
    "appspot.com": ("Google App Engine", "Cloud"),
    "fastly.net": ("Fastly", "CDN"),
    "akamai.net": ("Akamai", "CDN/WAF"),
    "akamaiedge.net": ("Akamai", "CDN/WAF"),
    "edgesuite.net": ("Akamai", "CDN/WAF"),
    "cloudflare.net": ("Cloudflare", "CDN/WAF"),
    "cdn77.org": ("CDN77", "CDN"),
    "vercel-dns.com": ("Vercel", "Cloud/CDN"),
    "netlify.com": ("Netlify", "Cloud/CDN"),
}
CLOUD_ORG_PATTERNS = {
    "cloudflare": "Cloudflare",
    "amazon": "AWS",
    "amazon.com": "AWS",
    "google": "Google Cloud",
    "microsoft": "Microsoft Azure",
    "azure": "Microsoft Azure",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "digitalocean": "DigitalOcean",
    "oracle": "Oracle Cloud",
    "linode": "Akamai/Linode",
    "ovh": "OVHcloud",
    "vultr": "Vultr",
    "hetzner": "Hetzner",
}


def normalize_scope(value: str) -> str:
    parsed = urlparse(value if "://" in value else "https://" + value)
    return (parsed.hostname or "").lower().rstrip(".")


def in_scope_url(value: str, scope: str) -> bool:
    try:
        host = (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return bool(host and (host == scope or host.endswith("." + scope)))


def in_scope_host(value: str, scope: str) -> bool:
    host = value.lower().rstrip(".")
    return host == scope or host.endswith("." + scope)


def extract_in_scope_hosts(text: str, scope: str) -> set[str]:
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)*{re.escape(scope)}(?![A-Za-z0-9_.-])",
        re.I,
    )
    return {match.group(0).lower().rstrip(".") for match in pattern.finditer(text)}


def normalized_url(raw: str) -> str | None:
    raw = html.unescape(raw.strip().rstrip(".,;)]}"))
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    decoded = unquote(unquote(raw)).lower()
    if any(marker in decoded for marker in ("{{", "}}", "${", "'+", '"+', ".concat(", "<%")):
        return None
    netloc = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    if port:
        netloc += f":{port}"
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))


def is_interesting_path(path: str) -> bool:
    lowered = path.lower().split("?", 1)[0]
    if lowered in SENSITIVE_PATHS:
        return True
    if any(marker in lowered for marker in EDITORIAL_PATH_MARKERS):
        return False
    return any(marker in lowered for marker in INTEREST_MARKERS) or lowered in {"/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"}


def fuzz_path_priority(path: str) -> tuple[int, int, str]:
    lowered = path.lower()
    if lowered in SENSITIVE_PATHS:
        rank = 0
    elif any(marker in lowered for marker in ("admin", "manage", "backoffice", "painel", "console", "login", "signin", "auth")):
        rank = 1
    elif any(marker in lowered for marker in ("swagger", "openapi", "api-docs", "graphql", "graphiql", "redoc", "/docs")):
        rank = 2
    elif any(marker in lowered for marker in ("actuator", "metrics", "debug", "server-status", "phpinfo", "trace")):
        rank = 3
    elif any(marker in lowered for marker in ("robots", "sitemap", "/api")):
        rank = 4
    else:
        rank = 5
    return rank, len(path), path


def looks_like_api(value: str) -> bool:
    lowered = value.lower()
    return bool(
        re.search(r"/(?:api|rest|graphql|gql|rpc|oauth|openid|swagger)(?:[/?.#_-]|$)", lowered)
        or re.search(r"/v[1-9](?:[/?.#_-]|$)", lowered)
    )


def add_api_endpoint(
    index: dict[tuple[str, str], dict[str, Any]],
    raw_url: str,
    method: str,
    source: str,
    scope: str,
    base_url: str,
    forced: bool = False,
) -> None:
    candidate = normalized_url(urljoin(base_url, html.unescape(raw_url.replace("\\/", "/"))))
    if not candidate or not in_scope_url(candidate, scope):
        return
    parsed = urlparse(candidate)
    api_path_match = re.search(r"/(?:api|rest|graphql|gql|rpc|oauth|openid|swagger)(?:/|$)", parsed.path, re.I)
    if api_path_match and any(marker in parsed.path[:api_path_match.start()] for marker in ("{", "}")):
        candidate = urlunparse((parsed.scheme, parsed.netloc, parsed.path[api_path_match.start():], parsed.params, parsed.query, ""))
        parsed = urlparse(candidate)
    suffix = Path(parsed.path).suffix.lower()
    lowered = (parsed.path + "?" + parsed.query).lower()
    decoded_path = unquote(parsed.path).lower()
    if "//" in parsed.path or re.search(r"<[^>]+>|(?:src|href)\s*=|[\"']|\s", decoded_path):
        return
    basename = parsed.path.rstrip("/").rsplit("/", 1)[-1].lower()
    config_identifier = bool(re.fullmatch(r"(?:api[_-]?(?:key|root|url|base|host)|base[_-]?(?:api|url))", basename))
    if suffix in SKIP_EXTENSIONS or suffix in JS_EXTENSIONS or config_identifier or (not forced and not looks_like_api(lowered)):
        return
    parameters = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    if parameters:
        candidate = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode([(key, "") for key in parameters]), ""))
    normalized_method = method.upper() if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} else "UNKNOWN"
    if normalized_method == "UNKNOWN":
        known = [row for (existing_method, existing_url), row in index.items() if existing_url == candidate and existing_method != "UNKNOWN"]
        if known:
            for row in known:
                row["sources"].add(source)
            return
    else:
        unknown = index.pop(("UNKNOWN", candidate), None)
    key = (normalized_method, candidate)
    row = index.setdefault(key, {"method": normalized_method, "url": candidate, "parameters": parameters, "sources": set(), "confidence": "medium"})
    if normalized_method != "UNKNOWN" and unknown:
        row["sources"].update(unknown.get("sources", []))
    row["sources"].add(source)
    if forced:
        row["confidence"] = "high"


def inferred_http_method(prefix: str) -> str:
    patterns = (
        r"(?i)\bmethod\s*[:=]\s*[\"']?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']?\s*[,;]?\s*$",
        r"(?i)(?:^|[\s([])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+$",
    )
    for pattern in patterns:
        match = re.search(pattern, prefix)
        if match:
            return match.group(1).upper()
    return "UNKNOWN"


def extract_api_endpoints(
    text: str,
    source: str,
    scope: str,
    base_url: str,
    index: dict[tuple[str, str], dict[str, Any]],
) -> None:
    for match in URL_RE.finditer(text):
        method = inferred_http_method(text[max(0, match.start() - 100):match.start()])
        add_api_endpoint(index, match.group(0), method, source, scope, base_url)
    for match in API_CALL_RE.finditer(text):
        call = match.group("call").lower()
        method = match.group("axios") or match.group("jquery") or ("GET" if call in {"fetch", "$.get"} else "UNKNOWN")
        if call == "fetch":
            call_tail = text[match.end():match.end() + 300]
            call_tail = call_tail.split(")", 1)[0]
            configured = re.search(r"(?i)\bmethod\s*:\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']", call_tail)
            if configured:
                method = configured.group(1)
        add_api_endpoint(index, match.group("url"), method or "UNKNOWN", source, scope, base_url, forced=True)
    for match in XHR_OPEN_RE.finditer(text):
        add_api_endpoint(index, match.group("url"), match.group("method"), source, scope, base_url, forced=True)
    for match in API_PATH_RE.finditer(text):
        method = inferred_http_method(text[max(0, match.start() - 100):match.start()])
        add_api_endpoint(index, match.group("url"), method, source, scope, base_url)


def extract_structured_api(
    text: str,
    source: str,
    scope: str,
    base_url: str,
    index: dict[tuple[str, str], dict[str, Any]],
) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return

    def walk(value: Any, method: str = "UNKNOWN", key_name: str = "") -> None:
        if isinstance(value, dict):
            local_method = str(value.get("method") or value.get("http_method") or method).upper()
            local_sources = []
            for candidate_source in value.get("sources") or []:
                candidate_source = str(candidate_source).strip()
                normalized_source = normalized_url(candidate_source)
                if normalized_source and in_scope_url(normalized_source, scope):
                    local_sources.append(normalized_source)
            if not local_sources:
                direct_source = str(value.get("source_url") or value.get("source") or "").strip()
                normalized_source = normalized_url(direct_source)
                if normalized_source and in_scope_url(normalized_source, scope):
                    local_sources.append(normalized_source)
            effective_sources = local_sources or [source]
            for key, child in value.items():
                key_lower = str(key).lower()
                if isinstance(child, str) and key_lower in {"url", "uri", "endpoint", "route", "path", "href"}:
                    forced = key_lower in {"endpoint", "route"} or looks_like_api(child)
                    for effective_source in effective_sources:
                        add_api_endpoint(index, child, local_method, effective_source, scope, base_url, forced=forced)
                walk(child, local_method, key_lower)
        elif isinstance(value, list):
            for child in value:
                walk(child, method, key_name)
        elif isinstance(value, str) and key_name in {"endpoints", "routes", "apis"}:
            add_api_endpoint(index, value, method, source, scope, base_url, forced=True)

    walk(data)


def serialized_api_endpoints(index: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    urls_with_method = {url for method, url in index if method != "UNKNOWN"}
    for row in index.values():
        if row["method"] == "UNKNOWN" and row["url"] in urls_with_method:
            continue
        sources = sorted(row.get("sources", []), key=lambda value: (not str(value).startswith(("http://", "https://")), str(value)))
        web_sources = [value for value in sources if str(value).startswith(("http://", "https://"))]
        rows.append({
            "method": row["method"],
            "url": row["url"],
            "parameters": row.get("parameters", []),
            "sources": web_sources or sources,
        })
    return sorted(rows, key=lambda row: (urlparse(row["url"]).hostname or "", urlparse(row["url"]).path, row["method"]))


def add_technology(
    index: dict[tuple[str, str, str], dict[str, Any]],
    host: str,
    name: str,
    version: str,
    source: str,
    evidence: str,
) -> None:
    name = re.sub(r"\s+", " ", name).strip()[:100]
    version = re.sub(r"[^A-Za-z0-9._+-]", "", version).strip()[:60]
    if not host or not name:
        return
    key = (host.lower(), name.lower(), version.lower())
    row = index.setdefault(key, {"host": host.lower(), "name": name, "version": version, "sources": set(), "evidence": set()})
    if source:
        row["sources"].add(source)
    if evidence:
        row["evidence"].add(evidence[:300])


def detect_technologies(
    url: str,
    headers: dict[str, str],
    text: str,
    index: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    host = urlparse(url).hostname or ""
    lowered_headers = {str(key).lower(): str(value) for key, value in headers.items()}
    for header_name in ("server", "x-powered-by", "x-generator"):
        value = lowered_headers.get(header_name, "").strip()
        if not value:
            continue
        match = re.match(r"\s*([^/;,(]+?)(?:[/ ](\d[\w.+-]*))?(?:[;,(]|$)", value.split()[0])
        if match:
            add_technology(index, host, match.group(1), match.group(2) or "", url, f"{header_name}: {value}")
    cookie = lowered_headers.get("set-cookie", "")
    for marker, name in (("laravel_session", "Laravel"), ("phpsessid", "PHP"), ("jsessionid", "Java Servlet"), ("asp.net_sessionid", "ASP.NET")):
        if marker in cookie.lower():
            add_technology(index, host, name, "", url, f"cookie: {marker}")
    sample = text[:500_000]
    generator = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", sample, re.I)
    if generator:
        value = generator.group(1).strip()
        match = re.match(r"(.+?)(?:\s+|/)(\d[\w.+-]*)$", value)
        add_technology(index, host, match.group(1) if match else value, match.group(2) if match else "", url, f"meta generator: {value}")
    signatures = [
        (r"ng-version=[\"']([^\"']+)", "Angular"),
        (r"wp-(?:content|includes)/[^\"']+?[?&]ver=([0-9][\w.-]+)", "WordPress"),
        (r"Drupal\.settings|/sites/default/files/", "Drupal"),
        (r"__NEXT_DATA__|/_next/static/", "Next.js"),
        (r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__", "React"),
    ]
    for pattern, name in signatures:
        match = re.search(pattern, sample, re.I)
        if match:
            version = match.group(1) if match.lastindex else ""
            add_technology(index, host, name, version, url, f"assinatura HTML/JS: {name}")


def collect_llm_technologies(
    result: dict[str, Any],
    scope: str,
    index: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    for item in result.get("technologies") or []:
        if isinstance(item, str):
            match = re.match(r"(.+?)(?:[/ ](\d[\w.+-]*))?$", item.strip())
            name, version, source_url = (match.group(1), match.group(2) or "", "") if match else (item, "", "")
        elif isinstance(item, dict):
            name = str(item.get("name") or "")
            version = str(item.get("version") or "")
            source_url = str(item.get("source_url") or "")
        else:
            continue
        normalized_source = normalized_url(source_url)
        if not normalized_source or not in_scope_url(normalized_source, scope):
            continue
        add_technology(index, urlparse(normalized_source).hostname or scope, name, version, normalized_source, "identificação semântica em conteúdo")


def serialized_technologies(index: dict[tuple[str, str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(({
        "host": row["host"],
        "name": row["name"],
        "version": row["version"],
        "sources": sorted(row["sources"]),
        "evidence": sorted(row["evidence"]),
    } for row in index.values()), key=lambda row: (row["host"], row["name"].lower(), row["version"]))


def is_text_file(path: Path) -> tuple[bool, str]:
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False, "extensão binária/visual ignorada"
    mime, _ = mimetypes.guess_type(path.name)
    if mime and (mime.startswith(("image/", "audio/", "video/", "font/")) or mime == "text/css"):
        return False, f"MIME {mime} ignorado"
    try:
        sample = path.read_bytes()[:8192]
    except OSError as exc:
        return False, f"leitura falhou: {exc}"
    if b"\x00" in sample:
        return False, "conteúdo binário ignorado"
    return True, ""


def extract_json(text: str) -> dict[str, Any]:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.I | re.S)
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {}


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.session = requests.Session()

    def check(self) -> None:
        response = self.session.get(self.base_url + "/api/tags", timeout=5)
        response.raise_for_status()

    def generate(self, prompt: str) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = self.session.post(
                    self.base_url + "/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.1, "num_ctx": 16384, "num_predict": 1400},
                    },
                    timeout=self.timeout,
                )
                response.raise_for_status()
                raw = response.json().get("response", "")[:MAX_RESPONSE_CHARS]
                return extract_json(raw)
            except Exception as exc:
                last_error = exc
                if attempt < 1:
                    time.sleep(1.5)
        raise RuntimeError(f"Ollama falhou após 2 tentativas: {last_error}")


def analysis_prompt(scope: str, source: str, part: int, total: int, content: str) -> str:
    return f"""Pentest autorizado de {scope}. Analise o pacote de evidências {part}/{total} ({source}).
Retorne no máximo 8 achados adicionais de alto sinal. Exija evidência literal, elimine duplicações, mascare segredos e não confunda palavra-chave com vulnerabilidade. Não transforme páginas de blog, conteúdo editorial, URL isolada ou resposta 404 em finding. URLs externas não fazem parte do escopo.
Priorize APIs, parâmetros, autenticação/OAuth/OIDC, credenciais plausíveis, configurações, painéis, arquivos expostos e sinks de XSS, SSRF ou path traversal. Para regra de negócio, reporte apenas lógica concreta de autorização, papéis, preços, estados, limites ou feature flags que possa alterar segurança, sempre com a fonte exata. Não declare takeover, bucket público, AXFR ou exploração confirmada sem a evidência específica do teste.
Responda SOMENTE JSON:
{{"findings":[{{"title":"...","category":"Segredos|Autenticação|OAuth/OIDC|Arquivos Sensíveis|Painéis|Regra de Negócio|Configuração|Correlação","severity":"critical|high|medium|low|info","confidence":"high|medium|low","target":"host ou URL","source_url":"URL exata onde a evidência foi encontrada","description":"...","evidence":"trecho curto e mascarado","recommendation":"...","urls":["..."]}}],"api_endpoints":[{{"method":"GET|POST|PUT|PATCH|DELETE|UNKNOWN","url":"URL absoluta reconstruída com o BASE da fonte","source_url":"JS ou página onde foi encontrado","evidence":"trecho curto"}}],"fuzz_paths":["/caminho"],"technologies":[{{"name":"...","version":"... ou vazio","source_url":"..."}}]}}

CONTEÚDO:
{content}"""


def safe_excerpt(value: str, limit: int = 1200) -> str:
    value = re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*)[^\s,;]+", r"\1\2[REDACTED]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*\b", "[JWT REDACTED]", value)
    return value[:limit]


def normalize_finding(raw: dict[str, Any], source: str, scope: str) -> dict[str, Any] | None:
    title = re.sub(r"\s+", " ", str(raw.get("title") or "")).strip()
    description = re.sub(r"\s+", " ", str(raw.get("description") or "")).strip()
    evidence = safe_excerpt(str(raw.get("evidence") or ""))
    if not title or not description or len(title) < 5 or len(evidence.strip()) < 5:
        return None
    severity = str(raw.get("severity") or "info").lower()
    confidence = str(raw.get("confidence") or "low").lower()
    if severity not in SEVERITY_RANK:
        severity = "info"
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    urls = []
    for value in raw.get("urls") or []:
        url = normalized_url(str(value))
        if url and in_scope_url(url, scope) and url not in urls:
            urls.append(url)
    target = str(raw.get("target") or (urls[0] if urls else scope))
    sources = []
    supplied_sources = list(raw.get("sources") or []) + [raw.get("source_url") or ""]
    for value in supplied_sources:
        value = str(value).strip()
        if not value or value in sources:
            continue
        normalized_source = normalized_url(value)
        if normalized_source and in_scope_url(normalized_source, scope):
            sources.append(normalized_source)
        elif not value.startswith(("http://", "https://")):
            sources.append(value[:500])
    if not sources:
        sources.append(source)
    return {
        "title": title[:220],
        "category": str(raw.get("category") or "Correlação")[:80],
        "severity": severity,
        "confidence": confidence,
        "target": target[:500],
        "description": description[:1800],
        "evidence": evidence,
        "recommendation": str(raw.get("recommendation") or "Valide manualmente no escopo autorizado.")[:1200],
        "urls": urls[:50],
        "sources": sources[:20],
        "validation": "llm-analysis",
    }


def collect_llm_api_endpoints(
    result: dict[str, Any],
    source: str,
    scope: str,
    base_url: str,
    index: dict[tuple[str, str], dict[str, Any]],
) -> None:
    for item in result.get("api_endpoints") or []:
        if not isinstance(item, dict):
            continue
        raw_url = str(item.get("url") or item.get("endpoint") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        if not raw_url.lower().startswith(("http://", "https://")) or len(evidence) < 3:
            continue
        source_url = normalized_url(str(item.get("source_url") or ""))
        endpoint_source = source_url if source_url and in_scope_url(source_url, scope) else source + " (LLM)"
        add_api_endpoint(index, raw_url, str(item.get("method") or "UNKNOWN"), endpoint_source, scope, base_url, forced=True)


def high_signal_excerpt(text: str, max_chars: int) -> str:
    if not text or max_chars <= 0:
        return ""
    snippets: list[str] = []
    seen: set[str] = set()
    used = 0
    for match in SIGNAL_RE.finditer(text):
        start = max(0, match.start() - 180)
        end = min(len(text), match.end() + 260)
        snippet = re.sub(r"\s+", " ", text[start:end]).strip()
        key = hashlib.sha1(snippet.encode(errors="ignore")).hexdigest()
        if not snippet or key in seen:
            continue
        seen.add(key)
        remaining = max_chars - used
        if remaining <= 0:
            break
        snippet = snippet[:remaining]
        snippets.append(snippet)
        used += len(snippet) + 1
    return "\n".join(snippets)[:max_chars]


def build_semantic_batches(
    evidence: list[dict[str, Any]],
    max_calls: int,
    batch_chars: int,
    source_chars: int,
) -> tuple[list[str], int]:
    if max_calls <= 0:
        return [], 0
    selected_sources = 0
    batches: list[str] = []
    current: list[str] = []
    current_size = 0
    seen: set[tuple[str, str]] = set()
    for item in sorted(evidence, key=lambda row: (row.get("priority", 9), row.get("source", ""))):
        excerpt = str(item.get("excerpt") or "")[:source_chars].strip()
        source = str(item.get("source") or "unknown")
        if not excerpt:
            continue
        fingerprint = hashlib.sha1(excerpt.encode(errors="ignore")).hexdigest()
        if (source, fingerprint) in seen:
            continue
        seen.add((source, fingerprint))
        block = f"[SOURCE: {source} | BASE: {item.get('base_url', '')}]\n{excerpt}\n"
        if current and current_size + len(block) > batch_chars:
            batches.append("\n".join(current))
            if len(batches) >= max_calls:
                break
            current, current_size = [], 0
        current.append(block)
        current_size += len(block)
        selected_sources += 1
    if current and len(batches) < max_calls:
        batches.append("\n".join(current))
    return batches, selected_sources


def body_fingerprint(body: str) -> str:
    normalized = re.sub(r"[0-9a-f]{8,}", "<dynamic>", body.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()[:100_000]
    return hashlib.sha256(normalized.encode()).hexdigest()


def request_in_scope(session: requests.Session, url: str, scope: str, timeout: float, max_bytes: int = 2 * 1024 * 1024):
    current = url
    for _ in range(5):
        if not in_scope_url(current, scope):
            raise ValueError("URL fora do escopo")
        response = session.get(current, timeout=timeout, verify=False, allow_redirects=False, stream=True, headers={"User-Agent": "W-BRID-AI/1.0"})
        if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("Location"):
            next_url = urljoin(current, response.headers["Location"])
            response.close()
            if not in_scope_url(next_url, scope):
                raise ValueError("redirecionamento externo bloqueado")
            current = next_url
            continue
        data = bytearray()
        for chunk in response.iter_content(65536):
            if not chunk:
                continue
            data.extend(chunk[: max_bytes - len(data)])
            if len(data) >= max_bytes:
                break
        encoding = response.encoding or "utf-8"
        text = bytes(data).decode(encoding, errors="replace")
        result = {"url": current, "status": response.status_code, "headers": dict(response.headers), "text": text, "bytes": len(data)}
        response.close()
        return result
    raise ValueError("excesso de redirecionamentos")


def classify_page(url: str, status: int, headers: dict[str, str], text: str, baseline_hash: str) -> dict[str, Any] | None:
    if status not in range(200, 400) or not text:
        return None
    if baseline_hash and body_fingerprint(text) == baseline_hash:
        return None
    lowered = text[:200_000].lower()
    path = urlparse(url).path.lower()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else ""
    category, severity, confidence = "Página Descoberta", "low", "medium"
    description = f"O caminho retornou HTTP {status}" + (f" com título '{title}'." if title else ".")
    if path in SENSITIVE_PATHS:
        env = len(re.findall(r"(?m)^[A-Z_][A-Z0-9_]{2,}\s*=", text)) >= 2
        git = "[core]" in lowered and "repositoryformatversion" in lowered
        config = path.startswith("/config.") and not re.search(r"<(?:html|body)\b", text[:2000], re.I) and bool(re.search(r"(?i)(api[_-]?key|client[_-]?secret|password|database[_-]?(?:url|host)|oauth|endpoint)\s*[\"']?\s*[:=]", text[:200_000]))
        archive = path.endswith(".zip") and (text.startswith("PK\x03\x04") or "zip" in headers.get("Content-Type", "").lower())
        sql_dump = path.endswith(".sql") and bool(re.search(r"(?im)^\s*(?:CREATE\s+TABLE|INSERT\s+INTO|--\s+(?:MySQL|PostgreSQL))", text[:200_000]))
        if not (env or git or config or archive or sql_dump):
            return None
        category, severity, confidence = "Arquivos Sensíveis", "critical" if env else "high", "high"
        signature = "arquivo .env" if env else "repositório Git" if git else "configuração" if config else "arquivo ZIP" if archive else "dump SQL"
        description = f"Conteúdo compatível com {signature} foi confirmado por assinatura, sem expor valores no relatório."
    elif "index of /" in lowered or "directory listing for" in lowered:
        category, severity, confidence = "Index Listing", "medium", "high"
        description = "A resposta apresenta assinatura de listagem de diretório."
    elif any(marker in path for marker in ("login", "signin", "auth", "sso", "oauth", "reset-password", "forgot-password")) or "type=\"password\"" in lowered:
        category, severity, confidence = "Autenticação", "info", "high"
        description = "Página ou fluxo de autenticação identificado."
    elif any(marker in path for marker in ("admin", "administrator", "manage", "backoffice", "painel", "dashboard", "console", "cpanel", "wp-admin", "phpmyadmin", "adminer", "jenkins", "grafana", "kibana")):
        category, severity = "Painéis", "medium" if status < 300 else "low"
        description = "Painel administrativo ou operacional acessível sem autenticação prévia observável nesta requisição."
    elif any(marker in path for marker in ("swagger", "openapi", "api-docs", "graphql", "graphiql", "redoc", "/api/docs", "/docs")):
        category, severity = "Documentação/API", "medium"
        description = "Documentação ou interface de API exposta foi identificada."
    elif any(marker in path for marker in ("actuator", "metrics", "debug", "server-status", "phpinfo", "trace")):
        category, severity = "Debug/Monitoramento", "high" if any(x in lowered for x in ("environment", "server variables", "php version")) else "medium"
        description = "Endpoint de debug, status ou monitoramento respondeu com conteúdo distinto do baseline."
    else:
        return None
    return {
        "title": f"{category}: {path or '/'}",
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "target": url,
        "description": description,
        "evidence": f"GET {url}\nHTTP {status}\nContent-Type: {headers.get('Content-Type', '')}\nTítulo: {title or '(ausente)'}",
        "recommendation": "Revise a necessidade de exposição, autenticação, autorização e conteúdo retornado.",
        "urls": [url],
        "sources": ["ai-fuzzing"],
        "validation": "http-confirmed",
    }


def discover_robots_and_sitemaps(
    session: requests.Session,
    origins: set[str],
    scope: str,
    timeout: float,
    url_inventory: set[str],
    fuzz_paths: set[str],
    api_index: dict[tuple[str, str], dict[str, Any]],
    sitemap_limit: int,
    sitemap_url_limit: int,
    workers: int,
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    robots_rows: list[dict[str, Any]] = []
    sitemap_rows: list[dict[str, Any]] = []
    documents: list[tuple[str, str]] = []
    sitemap_queue: list[str] = []
    queued: set[str] = set()

    origin_list = sorted(origins)
    for origin in origin_list:
        sitemap_queue.append(origin.rstrip("/") + "/sitemap.xml")

    def fetch_robots(origin: str):
        robots_url = origin.rstrip("/") + "/robots.txt"
        try:
            return request_in_scope(requests.Session(), robots_url, scope, timeout, 2 * 1024 * 1024)
        except Exception:
            if origin.startswith("https://") and urlparse(origin).port in {None, 443}:
                try:
                    return request_in_scope(requests.Session(), "http://" + origin[8:].rstrip("/") + "/robots.txt", scope, timeout, 2 * 1024 * 1024)
                except Exception:
                    pass
            return None

    robot_results = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = [executor.submit(fetch_robots, origin) for origin in origin_list]
        for future in as_completed(futures):
            result = future.result()
            if result:
                robot_results.append(result)

    for result in robot_results:
        text = result["text"]
        if result["status"] >= 400 or not text or re.search(r"<(?:html|body)\b", text[:2000], re.I):
            continue
        directives: list[dict[str, str]] = []
        for line in text.splitlines():
            match = re.match(r"\s*(Allow|Disallow|Sitemap)\s*:\s*(.*?)\s*$", line, re.I)
            if not match or not match.group(2):
                continue
            name, value = match.group(1).title(), match.group(2).strip()
            directives.append({"directive": name, "value": value})
            if name == "Sitemap":
                candidate = normalized_url(urljoin(result["url"], value))
                if candidate and in_scope_url(candidate, scope):
                    sitemap_queue.append(candidate)
            elif value.startswith("/") and "*" not in value and "$" not in value and len(value) < 300:
                path_value = value.split("?", 1)[0]
                if is_interesting_path(path_value):
                    fuzz_paths.add(path_value)
                candidate = normalized_url(urljoin(result["url"], value))
                if candidate:
                    url_inventory.add(candidate)
                    add_api_endpoint(api_index, candidate, "UNKNOWN", result["url"], scope, result["url"])
        robots_rows.append({"url": result["url"], "status": result["status"], "directives": directives})
        documents.append((result["url"], text[:CHUNK_CHARS]))
        extract_api_endpoints(text, result["url"], scope, result["url"], api_index)

    processed = 0
    discovered_urls = 0
    while sitemap_queue and processed < sitemap_limit and discovered_urls < sitemap_url_limit:
        sitemap_url = sitemap_queue.pop(0)
        normalized = normalized_url(sitemap_url)
        if not normalized or not in_scope_url(normalized, scope) or normalized in queued:
            continue
        queued.add(normalized)
        try:
            result = request_in_scope(session, normalized, scope, timeout, 5 * 1024 * 1024)
        except Exception:
            parsed_sitemap = urlparse(normalized)
            if parsed_sitemap.scheme == "https" and parsed_sitemap.port in {None, 443}:
                sitemap_queue.append(urlunparse(("http", parsed_sitemap.hostname or "", parsed_sitemap.path, parsed_sitemap.params, parsed_sitemap.query, "")))
            continue
        text = result["text"]
        if result["status"] >= 400 or not text or "<loc" not in text.lower():
            if urlparse(result["url"]).path == "/sitemap.xml":
                origin = f"{urlparse(result['url']).scheme}://{urlparse(result['url']).netloc}"
                sitemap_queue.extend(origin + path for path in ("/sitemap_index.xml", "/sitemap-index.xml", "/sitemap.xml.gz"))
            continue
        processed += 1
        # O XML inteiro já foi processado deterministicamente; uma amostra estrutural
        # é suficiente para a correlação sem transformar sitemaps massivos em milhares de prompts.
        documents.append((result["url"], text[:CHUNK_CHARS]))
        extract_api_endpoints(text, result["url"], scope, result["url"], api_index)
        root_tag = ""
        locations: list[str] = []
        try:
            root = ET.fromstring(text)
            root_tag = root.tag.rsplit("}", 1)[-1].lower()
            locations = [(node.text or "").strip() for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() == "loc"]
        except ET.ParseError:
            locations = [html.unescape(item.strip()) for item in re.findall(r"<loc[^>]*>(.*?)</loc>", text, re.I | re.S)]
        accepted = 0
        for location in locations:
            if discovered_urls >= sitemap_url_limit:
                break
            candidate = normalized_url(urljoin(result["url"], location))
            if not candidate or not in_scope_url(candidate, scope):
                continue
            if root_tag == "sitemapindex" or urlparse(candidate).path.lower().endswith((".xml", ".xml.gz")):
                sitemap_queue.append(candidate)
                continue
            if candidate in url_inventory:
                continue
            url_inventory.add(candidate)
            parsed = urlparse(candidate)
            origins.add(f"{parsed.scheme}://{parsed.netloc}")
            accepted += 1
            discovered_urls += 1
            if 1 < len(parsed.path) < 300 and not Path(parsed.path).suffix and is_interesting_path(parsed.path):
                fuzz_paths.add(parsed.path)
            add_api_endpoint(api_index, candidate, "GET", result["url"], scope, result["url"])
        sitemap_rows.append({"url": result["url"], "status": result["status"], "urls_discovered": accepted})

    return {
        "robots": robots_rows,
        "sitemaps": sitemap_rows,
        "robots_processed": len(robots_rows),
        "sitemaps_processed": len(sitemap_rows),
        "sitemap_urls_discovered": discovered_urls,
    }, documents


def resolve_cname(host: str) -> str:
    if not DNS_AVAILABLE:
        return ""
    try:
        answers = dns.resolver.resolve(host, "CNAME", lifetime=5)
        return str(next(iter(answers)).target).lower().rstrip(".")
    except Exception:
        return ""


def dns_target_resolves(host: str) -> bool:
    if not DNS_AVAILABLE:
        return True
    for record_type in ("A", "AAAA"):
        try:
            if dns.resolver.resolve(host, record_type, lifetime=5):
                return True
        except Exception:
            continue
    return False


def header_infrastructure(headers: dict[str, str]) -> list[tuple[str, str, str]]:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    server = lowered.get("server", "").lower()
    checks = [
        ("Cloudflare", "CDN/WAF", "cf-ray", "cf-ray" in lowered or "cloudflare" in server),
        ("AWS CloudFront", "CDN/Cloud", "x-amz-cf-id", "x-amz-cf-id" in lowered or "cloudfront" in lowered.get("via", "").lower()),
        ("Akamai", "CDN/WAF", "AkamaiGHost/x-akamai-*", "akamai" in server or any(key.startswith("x-akamai") for key in lowered)),
        ("Fastly", "CDN", "x-served-by/x-timer", "x-served-by" in lowered and "x-timer" in lowered),
        ("Azure Front Door", "CDN/Cloud", "x-azure-ref", "x-azure-ref" in lowered),
        ("AWS", "Cloud", "x-amzn-requestid/x-amz-apigw-id", "x-amzn-requestid" in lowered or "x-amz-apigw-id" in lowered),
        ("Google Cloud", "Cloud/CDN", "gfe/x-cloud-trace-context", server in {"gfe", "google frontend"} or "x-goog-generation" in lowered or "x-cloud-trace-context" in lowered),
        ("Vercel", "Cloud/CDN", "x-vercel-id", "x-vercel-id" in lowered),
        ("Netlify", "Cloud/CDN", "x-nf-request-id", "x-nf-request-id" in lowered),
        ("Fly.io", "Cloud", "fly-request-id", "fly-request-id" in lowered),
        ("Imperva", "WAF/CDN", "x-iinfo", "x-iinfo" in lowered),
        ("Sucuri", "WAF/CDN", "x-sucuri-id", "x-sucuri-id" in lowered),
    ]
    return [(name, kind, evidence) for name, kind, evidence, matched in checks if matched]


def resolve_host_ips(host: str) -> set[str]:
    values: set[str] = set()
    if not DNS_AVAILABLE:
        return values
    for record_type in ("A", "AAAA"):
        try:
            values.update(str(answer) for answer in dns.resolver.resolve(host, record_type, lifetime=5))
        except Exception:
            continue
    return values


def inspect_ip_ownership(hosts: set[str], scope: str, workers: int, limit: int) -> tuple[list[dict[str, str]], int]:
    if not IPWHOIS_AVAILABLE or limit <= 0:
        return [], 0
    ip_hosts: dict[str, set[str]] = defaultdict(set)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = {executor.submit(resolve_host_ips, host): host for host in hosts if in_scope_host(host, scope)}
        for future in as_completed(futures):
            host = futures[future]
            for ip in future.result():
                try:
                    if ipaddress.ip_address(ip).is_global:
                        ip_hosts[ip].add(host)
                except ValueError:
                    continue
    selected_ips = sorted(ip_hosts)[:limit]

    def lookup(ip: str):
        try:
            data = IPWhois(ip).lookup_rdap(depth=0, retry_count=0, rate_limit_timeout=5)
        except Exception:
            return ip, "", "", ""
        description = str(data.get("asn_description") or "").strip()
        asn = str(data.get("asn") or "").strip()
        network = data.get("network") or {}
        organization = str(network.get("name") or description or "").strip()
        haystack = f"{description} {organization}".lower()
        provider = next((label for marker, label in CLOUD_ORG_PATTERNS.items() if marker in haystack), organization or description)
        return ip, provider, asn, description or organization

    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
        futures = [executor.submit(lookup, ip) for ip in selected_ips]
        for future in as_completed(futures):
            ip, provider, asn, description = future.result()
            if not provider:
                continue
            for host in sorted(ip_hosts[ip]):
                rows.append({
                    "host": host,
                    "ip": ip,
                    "provider": provider,
                    "type": "Cloud/ASN" if provider in set(CLOUD_ORG_PATTERNS.values()) else "Rede/ASN",
                    "evidence": f"IP {ip} · AS{asn or '?'} · {description}",
                })
    return sorted(rows, key=lambda row: (row["host"], row["provider"], row["ip"])), len(selected_ips)


def inspect_infrastructure_and_takeover(
    hosts: set[str],
    scope: str,
    timeout: float,
    workers: int,
) -> tuple[list[dict[str, str]], list[dict[str, Any]], int]:
    selected_hosts = sorted(item for item in hosts if in_scope_host(item, scope))

    def inspect_one(host: str):
        local_infra: list[dict[str, str]] = []
        local_findings: list[dict[str, Any]] = []
        cname = resolve_cname(host)
        response = None
        for scheme in ("https", "http"):
            try:
                response = request_in_scope(requests.Session(), f"{scheme}://{host}/", scope, timeout, 512 * 1024)
                break
            except Exception:
                continue
        if cname:
            for suffix, (provider, kind) in INFRA_CNAME_PROVIDERS.items():
                if cname == suffix or cname.endswith("." + suffix):
                    local_infra.append({"host": host, "provider": provider, "type": kind, "evidence": f"CNAME → {cname}"})
        if response:
            for provider, kind, signal in header_infrastructure(response["headers"]):
                local_infra.append({"host": host, "provider": provider, "type": kind, "evidence": f"HTTP header: {signal}"})
        if not cname:
            return local_infra, local_findings
        for suffix, (provider, fingerprint) in TAKEOVER_PROVIDERS.items():
            if cname != suffix and not cname.endswith("." + suffix):
                continue
            body = response["text"].lower() if response else ""
            signature = bool(fingerprint and fingerprint in body)
            dangling = not dns_target_resolves(cname)
            if not signature and not dangling:
                continue
            evidence = f"CNAME {host} → {cname}; provedor {provider}; " + (f"assinatura HTTP '{fingerprint}' confirmada" if signature else "destino CNAME sem A/AAAA")
            local_findings.append({
                "title": f"Possível subdomain takeover em {host}",
                "category": "Subdomain Takeover",
                "severity": "high",
                "confidence": "high" if signature else "medium",
                "target": host,
                "description": "O subdomínio aponta para um recurso de terceiro com evidência de recurso ausente. A possibilidade de reivindicação não foi executada.",
                "evidence": evidence,
                "recommendation": "Remova o CNAME órfão ou recrie e vincule o recurso no provedor; valide a reivindicação apenas com autorização específica.",
                "urls": [response["url"]] if response else [],
                "sources": ["dns-takeover-check"],
                "validation": "dns-and-provider-signature" if signature else "dns-dangling-cname",
            })
            break
        return local_infra, local_findings

    infrastructure: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    seen_infra: set[tuple[str, str, str]] = set()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = [executor.submit(inspect_one, host) for host in selected_hosts]
        for future in as_completed(futures):
            local_infra, local_findings = future.result()
            for item in local_infra:
                key = (item["host"], item["provider"], item["type"])
                if key not in seen_infra:
                    seen_infra.add(key)
                    infrastructure.append(item)
            findings.extend(local_findings)
    infrastructure.sort(key=lambda item: (item["host"], item["provider"], item["type"]))
    return infrastructure, findings, len(selected_hosts)


def check_zone_transfer(scope: str, timeout: float) -> tuple[list[dict[str, Any]], int, str]:
    if not DNS_AVAILABLE:
        return [], 0, "dnspython não instalado"
    checked = 0
    try:
        nameservers = sorted({str(answer.target).rstrip(".") for answer in dns.resolver.resolve(scope, "NS", lifetime=timeout)})
    except Exception as exc:
        return [], 0, f"consulta NS falhou: {type(exc).__name__}"
    for nameserver in nameservers:
        addresses: list[str] = []
        for record_type in ("A", "AAAA"):
            try:
                addresses.extend(str(answer) for answer in dns.resolver.resolve(nameserver, record_type, lifetime=timeout))
            except Exception:
                continue
        for address in addresses:
            checked += 1
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(address, scope, lifetime=timeout))
            except Exception:
                continue
            nodes = sorted(str(name) for name in zone.nodes.keys())
            finding = {
                "title": f"Transferência de zona DNS permitida por {nameserver}",
                "category": "DNS/Zone Transfer",
                "severity": "high",
                "confidence": "high",
                "target": nameserver,
                "description": f"O nameserver permitiu AXFR da zona {scope}, expondo {len(nodes)} nome(s) DNS.",
                "evidence": f"AXFR @{address} {scope} concluído. Amostra: {', '.join(nodes[:10])}",
                "recommendation": "Restrinja AXFR aos servidores secundários autorizados por ACL e TSIG.",
                "urls": [],
                "sources": ["dns-axfr-check"],
                "validation": "dns-axfr-confirmed",
            }
            return [finding], checked, ""
    return [], checked, ""


def replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(key, value if key == parameter else current) for key, current in pairs]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(replaced), parsed.fragment))


def active_parameter_checks(
    urls: set[str],
    scope: str,
    timeout: float,
    request_limit: int,
) -> tuple[list[dict[str, Any]], int]:
    if request_limit <= 0:
        return [], 0
    findings: list[dict[str, Any]] = []
    requests_made = 0
    tested_schema: set[tuple[str, str, str, tuple[str, ...]]] = set()
    for url in sorted(urls):
        if requests_made >= request_limit:
            break
        parsed = urlparse(url)
        parameters = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        if not parameters or Path(parsed.path).suffix.lower() in SKIP_EXTENSIONS:
            continue
        schema = (parsed.scheme, parsed.netloc, parsed.path, tuple(sorted(set(parameters))))
        if schema in tested_schema:
            continue
        tested_schema.add(schema)
        try:
            baseline = request_in_scope(requests.Session(), url, scope, timeout, 512 * 1024)
            requests_made += 1
        except Exception:
            continue
        baseline_lower = baseline["text"].lower()
        content_type = str(baseline["headers"].get("Content-Type", "")).lower()
        for parameter in sorted(set(parameters)):
            if requests_made >= request_limit:
                break
            lowered_parameter = parameter.lower()
            marker = "wbrid" + hashlib.sha1(f"{url}:{parameter}".encode()).hexdigest()[:10]
            if (lowered_parameter in XSS_PARAMETERS or "html" in content_type) and requests_made < request_limit:
                xss_value = f"'><{marker}>"
                try:
                    result = request_in_scope(requests.Session(), replace_query_parameter(url, parameter, xss_value), scope, timeout, 512 * 1024)
                    requests_made += 1
                except Exception:
                    result = None
                if result and xss_value in result["text"] and xss_value not in baseline["text"] and "html" in str(result["headers"].get("Content-Type", "")).lower():
                    findings.append({
                        "title": f"Reflexão HTML não codificada no parâmetro {parameter}",
                        "category": "XSS",
                        "severity": "medium",
                        "confidence": "medium",
                        "target": url,
                        "description": "Um marcador inerte com delimitadores HTML foi refletido sem codificação. Isso indica contexto potencial para XSS, mas nenhum JavaScript foi executado.",
                        "evidence": f"GET com parâmetro {parameter}; HTTP {result['status']}; marcador inerte {xss_value} refletido literalmente.",
                        "recommendation": "Valide o contexto de saída e aplique codificação contextual, sanitização e CSP adequada.",
                        "urls": [url],
                        "sources": ["active-parameter-check"],
                        "validation": "raw-html-reflection",
                    })
            if lowered_parameter in TRAVERSAL_PARAMETERS:
                signatures = [
                    ("../../../../../../etc/passwd", ("root:x:0:0:", "root:*:0:0:"), "Unix /etc/passwd"),
                    (r"..\..\..\..\windows\win.ini", ("[extensions]", "for 16-bit app support"), "Windows win.ini"),
                ]
                for payload_value, expected, label in signatures:
                    if requests_made >= request_limit:
                        break
                    try:
                        result = request_in_scope(requests.Session(), replace_query_parameter(url, parameter, payload_value), scope, timeout, 512 * 1024)
                        requests_made += 1
                    except Exception:
                        continue
                    result_lower = result["text"].lower()
                    if any(signature in result_lower and signature not in baseline_lower for signature in expected):
                        findings.append({
                            "title": f"Path traversal confirmado no parâmetro {parameter}",
                            "category": "Path Traversal",
                            "severity": "high",
                            "confidence": "high",
                            "target": url,
                            "description": f"A resposta apresentou assinatura do arquivo de sistema {label} após uma sequência de traversal.",
                            "evidence": f"Parâmetro {parameter}; HTTP {result['status']}; assinatura de {label} confirmada (conteúdo omitido).",
                            "recommendation": "Restrinja caminhos a uma allowlist, normalize o caminho canônico e impeça acesso fora do diretório esperado.",
                            "urls": [url],
                            "sources": ["active-parameter-check"],
                            "validation": "system-file-signature",
                        })
                        break
            if lowered_parameter in SSRF_PARAMETERS and requests_made < request_limit:
                canary = f"http://127.0.0.1:1/{marker}"
                try:
                    result = request_in_scope(requests.Session(), replace_query_parameter(url, parameter, canary), scope, timeout, 512 * 1024)
                    requests_made += 1
                except Exception:
                    result = None
                ssrf_signatures = ("connection refused", "econnrefused", "dial tcp", "failed to connect", "no route to host", "connectexception")
                if result:
                    result_lower = result["text"].lower()
                    matched = next((signature for signature in ssrf_signatures if signature in result_lower and signature not in baseline_lower), "")
                    if matched:
                        findings.append({
                            "title": f"Indício forte de SSRF no parâmetro {parameter}",
                            "category": "SSRF",
                            "severity": "high",
                            "confidence": "medium",
                            "target": url,
                            "description": "O backend aparenta ter tentado acessar um canário local não sensível. Endpoints de metadados de nuvem não foram consultados.",
                            "evidence": f"Parâmetro {parameter}; canário 127.0.0.1:1; resposta contém assinatura '{matched}'.",
                            "recommendation": "Implemente allowlist de destinos, bloqueie endereços privados/link-local após resolução DNS e valide redirecionamentos.",
                            "urls": [url],
                            "sources": ["active-parameter-check"],
                            "validation": "controlled-ssrf-canary",
                        })
    return findings, requests_made


def bucket_candidates(scope: str, hosts: set[str], limit: int) -> list[str]:
    if limit <= 0:
        return []
    root_label = scope.split(".", 1)[0]
    values = {scope.replace(".", "-"), scope.replace(".", ""), root_label}
    for host in hosts:
        if not in_scope_host(host, scope):
            continue
        prefix = host[:-len(scope)].strip(".")
        compact = host.replace(".", "-")
        values.add(compact)
        if prefix:
            normalized_prefix = prefix.replace(".", "-")
            values.update({f"{root_label}-{normalized_prefix}", f"{normalized_prefix}-{root_label}", f"{scope.replace('.', '-')}-{normalized_prefix}"})
    cleaned = []
    for value in values:
        value = re.sub(r"[^a-z0-9-]", "-", value.lower()).strip("-")
        value = re.sub(r"-+", "-", value)
        if 3 <= len(value) <= 63 and value not in cleaned:
            cleaned.append(value)
    return sorted(cleaned, key=lambda value: (len(value), value))[:limit]


def check_public_buckets(
    scope: str,
    hosts: set[str],
    timeout: float,
    limit: int,
    workers: int,
) -> tuple[list[dict[str, Any]], int]:
    candidates = bucket_candidates(scope, hosts, limit)
    if not candidates:
        return [], 0

    def check(provider: str, bucket: str, url: str):
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": "W-BRID-AI/1.0"})
        except Exception:
            return None
        body = response.text[:2_000_000]
        if response.status_code != 200 or not re.search(r"<(?:\w+:)?ListBucketResult\b", body, re.I):
            return None
        listed_name = re.search(r"<(?:\w+:)?Name>\s*([^<]+?)\s*</(?:\w+:)?Name>", body, re.I)
        if not listed_name or html.unescape(listed_name.group(1)).strip().lower() != bucket.lower():
            return None
        object_count = len(re.findall(r"<(?:\w+:)?Key>", body, re.I))
        return {
            "title": f"Bucket público derivado do escopo: {bucket}",
            "category": "Cloud Storage",
            "severity": "medium",
            "confidence": "medium",
            "target": url,
            "description": f"O serviço {provider} permitiu listagem pública do bucket derivado de nomes do domínio/subdomínios. A associação do bucket ao proprietário do escopo é nominal e deve ser confirmada.",
            "evidence": f"GET {url}; HTTP 200; assinatura ListBucketResult; {object_count} objeto(s) na amostra.",
            "recommendation": "Desative listagem/acesso público quando não intencional e aplique políticas de menor privilégio e Public Access Block equivalente.",
            "urls": [url],
            "sources": ["public-bucket-check"],
            "validation": "public-listing-confirmed",
        }

    jobs = []
    for bucket in candidates:
        jobs.append(("AWS S3", bucket, f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=5"))
        jobs.append(("Google Cloud Storage", bucket, f"https://storage.googleapis.com/{bucket}?max-keys=5"))
    findings = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = [executor.submit(check, *job) for job in jobs]
        for future in as_completed(futures):
            finding = future.result()
            if finding:
                findings.append(finding)
    return findings, len(jobs)


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def publish_dashboard(dashboard: Path, payload: dict[str, Any], status: str, error: str = "") -> None:
    assets = dashboard / "assets"
    data = dict(payload)
    data["status"] = status
    if error:
        data["error"] = error
    serialized = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    atomic_text(assets / "ai-data.js", "window.WBRID_AI_DATA=" + serialized + ";\n")
    atomic_text(assets / "ai-status.js", "window.WBRID_AI_STATUS=" + json.dumps({"status": status}, ensure_ascii=False) + ";\n")


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in findings:
        key = (
            re.sub(r"\W+", " ", item.get("title", "").lower()).strip(),
            item.get("category", "").lower(),
            urlparse(item.get("target", "")).hostname or item.get("target", ""),
        )
        current = groups.get(key)
        if current is None:
            groups[key] = item
            continue
        current["urls"] = sorted(set(current.get("urls", []) + item.get("urls", [])))[:100]
        current["sources"] = sorted(set(current.get("sources", []) + item.get("sources", [])))
        if SEVERITY_RANK.get(item.get("severity", "info"), 9) < SEVERITY_RANK.get(current.get("severity", "info"), 9):
            current["severity"] = item["severity"]
    return sorted(groups.values(), key=lambda row: (SEVERITY_RANK.get(row.get("severity", "info"), 9), row.get("category", ""), row.get("title", "")))


def validate_finding_urls(
    findings: list[dict[str, Any]],
    known_status: dict[str, int],
    scope: str,
    timeout: float,
    workers: int,
    limit: int = 120,
) -> dict[str, int]:
    candidates: set[str] = set()
    for finding in findings:
        values = list(finding.get("urls") or []) + list(finding.get("sources") or []) + [finding.get("target") or ""]
        for value in values:
            normalized = normalized_url(str(value))
            if normalized and in_scope_url(normalized, scope) and normalized not in known_status:
                candidates.add(normalized)
    selected = sorted(candidates, key=lambda url: (not any(marker in url.lower() for marker in INTEREST_MARKERS), url))[:limit]

    def fetch_status(url: str):
        try:
            result = request_in_scope(requests.Session(), url, scope, timeout, 128 * 1024)
            return url, int(result["status"])
        except Exception:
            return url, 0

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = [executor.submit(fetch_status, url) for url in selected]
        for future in as_completed(futures):
            url, status = future.result()
            known_status[url] = status
    return known_status


def filter_relevant_findings(findings: list[dict[str, Any]], status_by_url: dict[str, int]) -> list[dict[str, Any]]:
    relevant: list[dict[str, Any]] = []
    strong_categories = {
        "segredos", "autenticação", "oauth/oidc", "arquivos sensíveis", "painéis", "documentação/api",
        "debug/monitoramento", "index listing", "regra de negócio", "configuração", "xss", "ssrf",
        "path traversal", "subdomain takeover", "dns/zone transfer", "cloud storage",
    }
    for item in findings:
        category = str(item.get("category") or "").strip().lower()
        title = str(item.get("title") or "").lower()
        evidence = str(item.get("evidence") or "").lower()
        confirmed_active = item.get("validation") in {"system-file-signature", "controlled-ssrf-canary", "raw-html-reflection", "public-listing-confirmed", "dns-axfr-confirmed", "dns-and-provider-signature"}
        if category in {"página descoberta", "blog", "conteúdo", "seo", "tecnologia", "endpoints"}:
            continue
        urls = []
        had_scoped_urls = False
        for value in item.get("urls") or []:
            normalized = normalized_url(str(value))
            if not normalized:
                continue
            had_scoped_urls = True
            if status_by_url.get(normalized) == 404 and not confirmed_active:
                continue
            urls.append(normalized)
        target_url = normalized_url(str(item.get("target") or ""))
        target_status = status_by_url.get(target_url, 0) if target_url else 0
        if target_status == 404 and not urls and not confirmed_active:
            continue
        if had_scoped_urls and not urls and not confirmed_active:
            continue
        if re.search(r"(?:http(?:/\d(?:\.\d)?)?\s*[:=]?\s*404|status\s*[:=]\s*404)", evidence) and not urls:
            continue
        paths = [urlparse(url).path.lower() for url in urls]
        if target_url:
            paths.append(urlparse(target_url).path.lower())
        editorial_only = bool(paths) and all(any(marker in path for marker in EDITORIAL_PATH_MARKERS) for path in paths)
        if editorial_only and category not in {"segredos", "arquivos sensíveis", "regra de negócio", "configuração", "xss", "ssrf", "path traversal"}:
            continue
        if category not in strong_categories and item.get("validation") == "llm-analysis":
            signal_text = f"{title} {evidence}"
            if not SIGNAL_RE.search(signal_text):
                continue
        sources = []
        had_web_sources = False
        live_web_sources = False
        for value in item.get("sources") or []:
            normalized_source = normalized_url(str(value))
            if normalized_source:
                had_web_sources = True
                if status_by_url.get(normalized_source) != 404:
                    live_web_sources = True
                    sources.append(normalized_source)
            elif value:
                sources.append(str(value))
        if had_web_sources and not live_web_sources and item.get("validation") == "llm-analysis":
            continue
        item["urls"] = sorted(set(urls))[:50]
        item["sources"] = list(dict.fromkeys(sources))[:20]
        if target_status == 404 and item["urls"]:
            item["target"] = item["urls"][0]
        relevant.append(item)
    return relevant


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analisa integralmente outputs textuais e JS em escopo com Ollama local.")
    parser.add_argument("--out-dir", default="OUT-WEB-BIRD")
    parser.add_argument("--dashboard-dir", default="dashboard")
    parser.add_argument("--scope-domain", required=True)
    parser.add_argument("--model", default=os.environ.get("BIRD_AI_MODEL", "deepseek-r1:14b"))
    parser.add_argument("--ollama-url", default=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"))
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--http-timeout", type=float, default=7)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--fuzz-limit", type=int, default=100)
    parser.add_argument("--page-limit", type=int, default=1500, help="Máximo de páginas priorizadas para nova requisição HTTP; 0 remove o limite.")
    parser.add_argument("--sitemap-limit", type=int, default=60, help="Máximo de documentos sitemap processados.")
    parser.add_argument("--sitemap-url-limit", type=int, default=50_000, help="Máximo de URLs incorporadas a partir de sitemaps.")
    parser.add_argument("--active-web-limit", type=int, default=400, help="Orçamento total de requisições para probes de parâmetros.")
    parser.add_argument("--bucket-limit", type=int, default=50, help="Máximo de nomes derivados testados em cada provedor.")
    parser.add_argument("--rdap-limit", type=int, default=80, help="Máximo de IPs únicos enriquecidos por RDAP.")
    parser.add_argument("--dns-timeout", type=float, default=8)
    parser.add_argument("--llm-max-calls", type=int, default=int(os.environ.get("BIRD_AI_MAX_CALLS", "6")), help="Máximo de prompts semânticos enviados ao Ollama.")
    parser.add_argument("--llm-batch-chars", type=int, default=12_000)
    parser.add_argument("--llm-source-chars", type=int, default=600)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scope = normalize_scope(args.scope_domain)
    out_dir = Path(args.out_dir).resolve()
    dashboard = Path(args.dashboard_dir).resolve()
    scope_dir = out_dir / scope
    scope_dir.mkdir(parents=True, exist_ok=True)
    output = scope_dir / f"{scope}-bird-ai-findings.json"
    manifest_output = scope_dir / f"{scope}-bird-ai-manifest.json"
    payload: dict[str, Any] = {"scope_domain": scope, "findings": [], "coverage": {}}
    publish_dashboard(dashboard, payload, "processing")
    started = time.monotonic()
    client = OllamaClient(args.ollama_url, args.model, args.timeout)
    try:
        client.check()
    except Exception as exc:
        message = f"Ollama indisponível: {type(exc).__name__}: {exc}"
        publish_dashboard(dashboard, payload, "error", message)
        atomic_text(output, json.dumps(dict(payload, status="error", error=message), ensure_ascii=False, indent=2) + "\n")
        print(f"[ERRO] {message}", file=sys.stderr)
        return 2
    print(f"[AI] v{VERSION} · modo rápido · limite de {args.llm_max_calls} chamada(s) Ollama", flush=True)

    manifest: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    fuzz_paths = set(FUZZ_PATHS)
    urls: set[str] = set()
    origins: set[str] = set()
    hosts: set[str] = {scope}
    api_index: dict[tuple[str, str], dict[str, Any]] = {}
    technology_index: dict[tuple[str, str, str], dict[str, Any]] = {}
    semantic_evidence: list[dict[str, Any]] = []
    files_processed = files_eligible = bytes_processed = chunks_processed = chunks_expected = 0
    llm_failures = 0

    candidates = []
    for target_dir in sorted(out_dir.iterdir() if out_dir.is_dir() else []):
        if not target_dir.is_dir() or not in_scope_host(target_dir.name, scope):
            continue
        hosts.add(target_dir.name.lower().rstrip("."))
        for path in sorted(target_dir.rglob("*")):
            if path.is_symlink() or not path.is_file() or path.name.endswith(("-bird-ai-findings.json", "-bird-ai-manifest.json", "-bird-ai.log")):
                continue
            candidates.append(path)

    for index, path in enumerate(candidates, 1):
        allowed, reason = is_text_file(path)
        entry = {"path": str(path.relative_to(out_dir)), "bytes": path.stat().st_size, "processed": False, "reason": reason, "semantic_candidate": False}
        manifest.append(entry)
        if not allowed:
            continue
        files_eligible += 1
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="replace")
        except OSError as exc:
            entry["reason"] = f"leitura falhou: {exc}"
            continue
        source_host = path.parent.name if in_scope_host(path.parent.name, scope) else scope
        source_base = f"https://{source_host}/"
        hosts.update(extract_in_scope_hosts(text, scope))
        for source_match in URL_RE.finditer(text):
            source_url = normalized_url(source_match.group(0))
            if source_url and in_scope_url(source_url, scope):
                parsed_source = urlparse(source_url)
                source_base = f"{parsed_source.scheme}://{parsed_source.netloc}/"
                break
        extract_api_endpoints(text, entry["path"], scope, source_base, api_index)
        extract_structured_api(text, entry["path"], scope, source_base, api_index)
        for match in URL_RE.finditer(text):
            url = normalized_url(match.group(0))
            if url and in_scope_url(url, scope):
                urls.add(url)
                parsed = urlparse(url)
                hosts.add(parsed.hostname or scope)
                origins.add(f"{parsed.scheme}://{parsed.netloc}")
                path_value = parsed.path
                if 1 < len(path_value) < 180 and not Path(path_value).suffix and is_interesting_path(path_value):
                    fuzz_paths.add(path_value)
        excerpt = high_signal_excerpt(text, args.llm_source_chars)
        if excerpt:
            priority = 0 if any(marker in entry["path"].lower() for marker in ("bird-craftjs", "final-findings", ".js", ".map")) else 1
            semantic_evidence.append({"priority": priority, "source": entry["path"], "base_url": source_base, "excerpt": excerpt})
            entry["semantic_candidate"] = True
        entry["processed"] = True
        entry["reason"] = ""
        files_processed += 1
        bytes_processed += len(raw)
        print(f"[{index}/{len(candidates)}] {entry['path']} · triagem concluída", flush=True)

    session = requests.Session()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if not origins:
        origins.update({f"https://{scope}", f"http://{scope}"})
    origin_hosts = {urlparse(origin).hostname for origin in origins}
    origins.update(f"https://{host}" for host in hosts if host not in origin_hosts)
    discovery, discovery_documents = discover_robots_and_sitemaps(
        session,
        origins,
        scope,
        args.http_timeout,
        urls,
        fuzz_paths,
        api_index,
        args.sitemap_limit,
        args.sitemap_url_limit,
        args.workers,
    )
    network_documents_analyzed = 0
    for source, text in discovery_documents:
        excerpt = high_signal_excerpt(text, args.llm_source_chars)
        if excerpt:
            semantic_evidence.append({"priority": 1, "source": source, "base_url": source, "excerpt": excerpt})
        network_documents_analyzed += 1
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            hosts.add(parsed.hostname)
    baseline_by_origin: dict[str, str] = {}
    reachable_origins: set[str] = set()

    def fetch_baseline(origin: str):
        try:
            baseline = request_in_scope(requests.Session(), origin + "/.wbrid-not-found-6e2a9f", scope, args.http_timeout, 256 * 1024)
            return True, body_fingerprint(baseline["text"]) if baseline["status"] == 200 else ""
        except Exception:
            return False, ""

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as executor:
        futures = {executor.submit(fetch_baseline, origin): origin for origin in sorted(origins)}
        for future in as_completed(futures):
            origin = futures[future]
            reachable, fingerprint = future.result()
            baseline_by_origin[origin] = fingerprint
            if reachable:
                reachable_origins.add(origin)

    page_by_key: dict[tuple[Any, ...], str] = {}
    for url in sorted(urls):
        parsed = urlparse(url)
        suffix = Path(parsed.path).suffix.lower()
        if suffix in JS_EXTENSIONS or suffix in SKIP_EXTENSIONS:
            continue
        query_keys = tuple(sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
        key = (parsed.scheme, parsed.netloc, parsed.path or "/", query_keys)
        page_by_key.setdefault(key, url)

    def page_priority(url: str):
        parsed = urlparse(url)
        value = (parsed.path + "?" + parsed.query).lower()
        if parsed.path in SENSITIVE_PATHS:
            score = 0
        elif any(marker in value for marker in INTEREST_MARKERS):
            score = 1
        elif parsed.query:
            score = 2
        elif Path(parsed.path).suffix.lower() in {".json", ".xml", ".yml", ".yaml"}:
            score = 3
        elif any(marker in parsed.path.lower() for marker in EDITORIAL_PATH_MARKERS):
            score = 9
        else:
            score = 4
        return score, url

    all_page_candidates = sorted(page_by_key.values(), key=page_priority)
    page_candidates = all_page_candidates[:args.page_limit] if args.page_limit > 0 else all_page_candidates

    def fetch_page(url: str):
        try:
            result = request_in_scope(requests.Session(), url, scope, args.http_timeout, 1024 * 1024)
            result["requested_url"] = url
            return url, result
        except Exception:
            return url, None

    page_results = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as executor:
        futures = [executor.submit(fetch_page, url) for url in page_candidates]
        for future in as_completed(futures):
            _url, result = future.result()
            if result:
                page_results.append(result)

    page_documents_analyzed = 0
    status_by_url: dict[str, int] = {}
    seen_page_bodies: set[tuple[str, str]] = set()
    for result in page_results:
        status_by_url[result["url"]] = int(result["status"])
        status_by_url[result.get("requested_url", result["url"])] = int(result["status"])
        content_type = str(result["headers"].get("Content-Type", "")).lower()
        if content_type.startswith(("image/", "audio/", "video/", "font/")) or "text/css" in content_type:
            continue
        extract_api_endpoints(result["text"], result["url"], scope, result["url"], api_index)
        extract_structured_api(result["text"], result["url"], scope, result["url"], api_index)
        detect_technologies(result["url"], result["headers"], result["text"], technology_index)
        origin = f"{urlparse(result['url']).scheme}://{urlparse(result['url']).netloc}"
        classified = classify_page(result["url"], result["status"], result["headers"], result["text"], baseline_by_origin.get(origin, ""))
        if classified:
            findings.append(classified)
        if "html" in content_type or re.search(r"<(?:html|head|body|script)\b", result["text"][:5000], re.I):
            for match in re.finditer(r"<script[^>]+src\s*=\s*[\"']([^\"']+)", result["text"], re.I):
                script_url = normalized_url(urljoin(result["url"], html.unescape(match.group(1))))
                if script_url and in_scope_url(script_url, scope) and Path(urlparse(script_url).path).suffix.lower() in JS_EXTENSIONS:
                    urls.add(script_url)
                    if urlparse(script_url).hostname:
                        hosts.add(urlparse(script_url).hostname or scope)
        fingerprint = (origin, body_fingerprint(result["text"]))
        if not result["text"] or fingerprint in seen_page_bodies:
            continue
        seen_page_bodies.add(fingerprint)
        excerpt = high_signal_excerpt(result["text"], args.llm_source_chars)
        if excerpt:
            semantic_evidence.append({"priority": 2, "source": result["url"], "base_url": result["url"], "excerpt": excerpt})
        page_documents_analyzed += 1

    js_urls = sorted(url for url in urls if Path(urlparse(url).path).suffix.lower() in JS_EXTENSIONS)
    js_analyzed = 0
    for index, url in enumerate(js_urls, 1):
        try:
            result = request_in_scope(session, url, scope, args.http_timeout, 5 * 1024 * 1024)
        except Exception:
            continue
        content_type = str(result["headers"].get("Content-Type", "")).lower()
        if "text/html" in content_type or re.search(r"<(?:html|body|head)\b", result["text"][:3000], re.I):
            continue
        js_analyzed += 1
        js_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
        extract_api_endpoints(result["text"], url, scope, js_origin, api_index)
        extract_structured_api(result["text"], url, scope, js_origin, api_index)
        detect_technologies(url, result["headers"], result["text"], technology_index)
        excerpt = high_signal_excerpt(result["text"], args.llm_source_chars)
        if excerpt:
            semantic_evidence.append({"priority": 0, "source": url, "base_url": js_origin, "excerpt": excerpt})
        print(f"[JS {index}/{len(js_urls)}] {url} · triagem concluída", flush=True)

    semantic_batches, semantic_sources_selected = build_semantic_batches(
        semantic_evidence,
        args.llm_max_calls,
        args.llm_batch_chars,
        args.llm_source_chars,
    )
    chunks_expected = len(semantic_batches)
    for part_index, batch in enumerate(semantic_batches, 1):
        try:
            llm_result = client.generate(analysis_prompt(scope, "EVIDÊNCIAS PRIORIZADAS", part_index, len(semantic_batches), batch))
        except Exception as exc:
            llm_failures += 1
            print(f"[LLM {part_index}/{len(semantic_batches)}] falhou: {type(exc).__name__}", file=sys.stderr, flush=True)
            continue
        chunks_processed += 1
        collect_llm_api_endpoints(llm_result, f"semantic-batch-{part_index}", scope, f"https://{scope}/", api_index)
        collect_llm_technologies(llm_result, scope, technology_index)
        for raw_finding in llm_result.get("findings") or []:
            if isinstance(raw_finding, dict):
                finding = normalize_finding(raw_finding, f"semantic-batch-{part_index}", scope)
                if finding:
                    findings.append(finding)
        for path_value in llm_result.get("fuzz_paths") or []:
            path_value = str(path_value).strip()
            if path_value.startswith("/") and len(path_value) < 180 and ".." not in path_value and is_interesting_path(path_value):
                fuzz_paths.add(path_value)
        print(f"[LLM {part_index}/{len(semantic_batches)}] concluído", flush=True)

    selected_paths = sorted(fuzz_paths, key=fuzz_path_priority)[:args.fuzz_limit]
    fuzz_tested = 0

    def fuzz_one(origin: str, path_value: str):
        url = origin.rstrip("/") + "/" + path_value.lstrip("/")
        try:
            result = request_in_scope(requests.Session(), url, scope, args.http_timeout, 512 * 1024)
        except Exception:
            return None
        return classify_page(result["url"], result["status"], result["headers"], result["text"], baseline_by_origin.get(origin, ""))

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as executor:
        futures = [executor.submit(fuzz_one, origin, path_value) for origin in sorted(reachable_origins) for path_value in selected_paths]
        for future in as_completed(futures):
            fuzz_tested += 1
            finding = future.result()
            if finding:
                findings.append(finding)

    zone_findings, zone_nameservers_checked, zone_diagnostic = check_zone_transfer(scope, args.dns_timeout)
    findings.extend(zone_findings)
    infrastructure, takeover_findings, infrastructure_hosts_checked = inspect_infrastructure_and_takeover(
        hosts, scope, args.http_timeout, args.workers
    )
    ip_infrastructure, rdap_ips_checked = inspect_ip_ownership(hosts, scope, args.workers, args.rdap_limit)
    infrastructure.extend(ip_infrastructure)
    infrastructure = sorted({
        (item.get("host", ""), item.get("ip", ""), item.get("provider", ""), item.get("type", ""), item.get("evidence", ""))
        for item in infrastructure
    })
    infrastructure = [
        {"host": host, "ip": ip, "provider": provider, "type": kind, "evidence": evidence}
        for host, ip, provider, kind, evidence in infrastructure
    ]
    findings.extend(takeover_findings)
    parameter_findings, active_parameter_requests = active_parameter_checks(
        urls, scope, args.http_timeout, args.active_web_limit
    )
    findings.extend(parameter_findings)
    bucket_findings, bucket_requests = check_public_buckets(
        scope, hosts, args.http_timeout, args.bucket_limit, args.workers
    )
    findings.extend(bucket_findings)

    status_by_url = validate_finding_urls(findings, status_by_url, scope, args.http_timeout, args.workers)
    findings = deduplicate_findings(filter_relevant_findings(findings, status_by_url))
    api_endpoints = serialized_api_endpoints(api_index)
    technologies = serialized_technologies(technology_index)
    coverage = {
        "files_total": len(candidates),
        "text_files_total": files_eligible,
        "files_processed": files_processed,
        "files_skipped": sum(1 for item in manifest if not item["processed"]),
        "bytes_processed": bytes_processed,
        "chunks_expected": chunks_expected,
        "chunks_processed": chunks_processed,
        "analysis_complete": files_processed == files_eligible,
        "urls_discovered": len(urls),
        "page_links_discovered": len(all_page_candidates),
        "page_links_selected": len(page_candidates),
        "page_links_fetched": len(page_results),
        "page_documents_analyzed": page_documents_analyzed,
        "js_discovered": len(js_urls),
        "js_analyzed": js_analyzed,
        "api_endpoints_discovered": len(api_endpoints),
        "robots_processed": discovery["robots_processed"],
        "sitemaps_processed": discovery["sitemaps_processed"],
        "sitemap_urls_discovered": discovery["sitemap_urls_discovered"],
        "network_documents_analyzed": network_documents_analyzed,
        "origins_discovered": len(origins),
        "origins_fuzzed": len(reachable_origins),
        "fuzz_requests": fuzz_tested,
        "active_parameter_requests": active_parameter_requests,
        "infrastructure_hosts_checked": infrastructure_hosts_checked,
        "infrastructure_signals": len(infrastructure),
        "rdap_ips_checked": rdap_ips_checked,
        "technologies_detected": len(technologies),
        "validated_404_urls": sum(1 for status in status_by_url.values() if status == 404),
        "zone_nameservers_checked": zone_nameservers_checked,
        "bucket_requests": bucket_requests,
        "semantic_evidence_candidates": len(semantic_evidence),
        "semantic_sources_selected": semantic_sources_selected,
        "llm_calls_planned": chunks_expected,
        "llm_calls_completed": chunks_processed,
        "llm_failures": llm_failures,
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    payload = {
        "schema_version": 1,
        "tool": "W-BRID AI Analysis",
        "version": VERSION,
        "status": "ready",
        "scope_domain": scope,
        "model": args.model,
        "generated_at": datetime.now().astimezone().isoformat(),
        "coverage": coverage,
        "discovery": discovery,
        "api_endpoints": api_endpoints,
        "infrastructure": infrastructure,
        "technologies": technologies,
        "diagnostics": (
            ([{"module": "zone_transfer", "message": zone_diagnostic}] if zone_diagnostic else [])
            + ([{"module": "ollama", "message": f"{llm_failures} lote(s) sem resposta após duas tentativas"}] if llm_failures else [])
        ),
        "findings": findings,
    }
    atomic_text(output, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    atomic_text(manifest_output, json.dumps({"scope_domain": scope, "coverage": coverage, "files": manifest}, ensure_ascii=False, indent=2) + "\n")
    publish_dashboard(dashboard, payload, "ready")
    print(f"[OK] {len(findings)} achado(s) adicionais · {files_processed}/{files_eligible} arquivo(s) textual(is) · {chunks_processed}/{chunks_expected} chamada(s) LLM · {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        fallback_args = parse_args()
        fallback_scope = normalize_scope(fallback_args.scope_domain)
        message = f"Falha não tratada: {type(exc).__name__}: {exc}"
        fallback_payload = {
            "schema_version": 1,
            "tool": "W-BRID AI Analysis",
            "version": VERSION,
            "status": "error",
            "scope_domain": fallback_scope,
            "coverage": {},
            "api_endpoints": [],
            "infrastructure": [],
            "technologies": [],
            "findings": [],
            "error": message,
        }
        fallback_output = Path(fallback_args.out_dir).resolve() / fallback_scope / f"{fallback_scope}-bird-ai-findings.json"
        atomic_text(fallback_output, json.dumps(fallback_payload, ensure_ascii=False, indent=2) + "\n")
        publish_dashboard(Path(fallback_args.dashboard_dir).resolve(), fallback_payload, "error", message)
        print(f"[ERRO] {message}", file=sys.stderr)
        raise SystemExit(1)
