# 🐉 LEVIATHAN OSINT v4.0
### *Framework de Inteligencia de Fuentes Abiertas*

**Creado por:** Luis Sánchez  
**Versión:** 4.0 | Python 3.10+ | Kali Linux · NetHunter · Termux · Ubuntu

> *"OSINT puro primero. La IA es el complemento, no la dependencia."*

```
Consensus Engine · Event Bus · 3 Microkernels · 41+ Módulos
FastText ML Local · SelfLearning · HealthCheck Background
Plugin System · Leviathan Abyss (Rich) + Textual TUI · REST API
```

---

## ⚠️ Aviso Legal

Leviathan está diseñado **exclusivamente** para uso **legal y ético**:

- ✅ Investigaciones de seguridad con **autorización explícita** del objetivo
- ✅ OSINT defensivo sobre infraestructura o personas **propias**
- ✅ Threat Intelligence y Brand Protection corporativa
- ✅ Investigación periodística y académica
- ✅ Incident Response post-breach
- ✅ Pentesting con scope definido y contrato firmado

**El usuario es el único responsable del uso de esta herramienta.**  
México: Art. 211 bis CPF — uso no autorizado contra terceros constituye delito federal.

---

## 📋 Índice

1. [¿Qué es Leviathan?](#1-qué-es-leviathan)
2. [Instalación](#2-instalación)
3. [Uso básico](#3-uso-básico)
4. [Todos los flags](#4-todos-los-flags)
5. [Variables de entorno](#5-variables-de-entorno)
6. [Dashboard TUI](#6-dashboard-tui)
7. [Arquitectura del sistema](#7-arquitectura-del-sistema)
8. [Los 41+ módulos](#8-los-41-módulos)
9. [Consensus Engine](#9-consensus-engine)
10. [ProfileComposite](#10-profilecomposite)
11. [FastText ML Local](#11-fasttext-ml-local)
12. [SelfLearning](#12-selflearning)
13. [HealthCheck Background](#13-healthcheck-background)
14. [Plugin System](#14-plugin-system)
15. [Módulo 49 MultiModal (opt-in)](#15-módulo-49-multimodal-opt-in)
16. [REST API](#16-rest-api)
17. [Batch Mode](#17-batch-mode)
18. [Graph Export](#18-graph-export)
19. [Configuración de APIs](#19-configuración-de-apis)
20. [Configuración completa](#20-configuración-completa)
21. [Source Genealogy](#21-source-genealogy)
22. [Executive Summary](#22-executive-summary)
23. [Seguridad operacional](#23-seguridad-operacional)
24. [Estructura del proyecto](#24-estructura-del-proyecto)
25. [Crear plugins](#25-crear-plugins)
26. [Roadmap v5.0](#26-roadmap-v50)

---

## 1. ¿Qué es Leviathan?

Leviathan es un framework OSINT diseñado en torno a cuatro principios fundamentales:

### Los módulos solo emiten, nunca juzgan

```python
# Así trabaja cualquier módulo de Leviathan:
async def _run(self, target):
    data = await self.get_json("https://api.ejemplo.com/" + target.normalized)
    if data and data.get("email"):
        self.emit("email", data["email"], {"source": "api_ejemplo"})
    # Eso es todo. Sin calcular confidence. Sin validar. Sin juzgar.
```

El **Consensus Engine** recibe ese dato y lo evalúa con validators independientes:
regex, MX record, breach check, source reputation, freshness bonus, Source Genealogy.
Un solo lugar donde se decide qué es verdad. Consistente. Explicable.

### Todo pasa por el Event Bus

```
módulo_09 emite NEW_ENTITY
    → Consensus Layer valida → ENTITY_CONFIRMED
        → K2 Correlator busca relaciones → CORRELATION_FOUND
            → K3 Storage persiste → ENTITY_PERSISTED
                → Dashboard actualiza en tiempo real
                → ProfileComposite se enriquece
                → FastText aprende
                → SelfLearning ajusta prioridades
```

Nadie habla con nadie directamente. Todo pasa por el bus.

### El sistema aprende de tu uso

FastText local aprende de cada entidad confirmada. Sin etiquetado manual.
Sin GPU. Sin internet. Los primeros 100 scans lo calibran, los siguientes 400
lo hacen confiable. El SelfLearning ajusta automáticamente qué módulos
correr primero según el tipo de target y región.

### El perfil se construye solo

Cuando hay suficientes entidades vinculadas al mismo pivot (email/phone/username),
el `ProfileCompositeBuilder` ensambla automáticamente una narrativa:

```
• Juan García López — ubicación: Culiacán, Sinaloa
• Primera huella digital: 2019-08 (6 años de actividad)
• Identidad: 2 emails; teléfono Telcel 667; GitHub, Telegram, Reddit
• E-commerce: MercadoLibre MX, Amazon México
• Breaches: RappiPay 2023 (credenciales), RockYou2021
• Patrones: developer_profile, online_shopper, messaging_apps
• Riesgo: 67/100 [ALTO]
```

---

## 2. Instalación

### Requisitos mínimos

- Python 3.10+
- 256 MB RAM (512 MB recomendado para FastText)
- Kali Linux / Ubuntu / Debian / NetHunter / Termux (ARM OK)

### Setup rápido

```bash
# 1. Descomprimir
unzip leviathan_v4.0.zip && cd leviathan

# 2. Venv
python3 -m venv venv && source venv/bin/activate
# Windows: .\venv\Scripts\activate

# 3. Setup automático
python3 setup.py

# 4. Dependencias base (mínimo)
pip install aiohttp aiofiles rich networkx pyyaml

# 5. Verificar
python leviathan.py --list-modules
python leviathan.py --apis
```

### Dependencias opcionales

```bash
# TUI avanzado con mouse y tabs
pip install textual                     # → usar con --textual

# TLS fingerprinting real (evitar bans Cloudflare/Akamai)
pip install curl_cffi

# REST API
pip install fastapi uvicorn

# Soporte Tor y proxies SOCKS
pip install aiohttp-socks

# FastText ML local (recomendado para ARM/Kali)
pip install fasttext-wheel              # ARM/Kali
# pip install fasttext                  # alternativa oficial Meta

# Grafos HTML standalone
pip install pyvis

# EXIF de imágenes (módulo 49)
pip install Pillow

# LLM local
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull phi3:mini                   # ligero — NetHunter/Termux
ollama pull qwen2.5:32b                 # potente — desktop 32GB RAM
ollama pull llama3.1:8b                 # balance peso/calidad

# Tor — módulos darkweb directos
sudo apt install tor && sudo service tor start

# Todo de una
pip install aiohttp aiofiles rich networkx pyyaml fastapi uvicorn \
            aiohttp-socks fasttext-wheel pyvis Pillow textual
```

---

## 3. Uso básico

```bash
# Email
python leviathan.py usuario@empresa.com

# Teléfono MX (múltiples formatos)
python leviathan.py "+52 664 123 4567"
python leviathan.py "6641234567"
python leviathan.py "664 123 4567"

# Dominio
python leviathan.py empresa.com
python leviathan.py www.empresa.com.mx

# IP
python leviathan.py 8.8.8.8
python leviathan.py 192.168.1.1        # detecta que es privada

# Username
python leviathan.py mi_usuario

# Nombre completo
python leviathan.py "Juan García López"
python leviathan.py "María de la Luz Hernández"

# Wallet crypto
python leviathan.py 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2    # BTC
python leviathan.py 0x742d35cc6634c0532925a3b8bc454e4438f44e # ETH

# Placa vehicular MX
python leviathan.py ABC-123-D
python leviathan.py "SIN 1234A"

# URL / Onion
python leviathan.py empresa.com
python leviathan.py abcdefghijklmnop.onion
```

---

## 4. Todos los flags

```bash
# ── TUI / Display ────────────────────────────────────────────────────
--no-tui              Solo logs en consola (más rápido, ideal para scripts)
--textual             Usar Textual TUI (mouse, tabs, scroll) — pip install textual
--output json         Output JSON estructurado (sin TUI, ideal para pipes)
--output text         Output texto legible (default)
--output quiet        Sin output en consola

# ── Red / Anonimato ──────────────────────────────────────────────────
--tor                 Usar Tor para anonimato (requiere: sudo service tor start)
--proxy URL           Proxy: socks5://user:pass@host:port | http://host:port
--concurrency N       Requests concurrentes — default 10 (K1_CONCURRENCY env)

# ── Módulos especiales ────────────────────────────────────────────────
--llm                 Activar análisis semántico con LLM local (requiere Ollama)
--llm-model MODEL     Modelo Ollama: phi3:mini (default) | qwen2.5:32b | llama3.1:8b
--llm-host URL        Host Ollama: http://localhost:11434 (default)
--deep-multimodal     Activar módulo 49 (EXIF metadata de imágenes públicas)
                      Requiere confirmación de autorización sobre el target

# ── Plugins ───────────────────────────────────────────────────────────
--plugins-dir DIR     Directorio de plugins (default: plugins/)
--list-plugins        Listar plugins instalados y su estado
--no-plugins          Deshabilitar carga de plugins

# ── Batch / API ───────────────────────────────────────────────────────
--batch FILE          Procesar lista de targets (txt/csv, uno por línea)
--api                 Iniciar REST API en http://localhost:PORT/docs
--port N              Puerto de la API (default: 8000)

# ── FastText ML ───────────────────────────────────────────────────────
--ft-status           Estado de todos los modelos FastText
--ft-train            Forzar re-entrenamiento de modelos FastText
--analyze-reports DIR Alimentar FastText con reportes JSON históricos

# ── Mantenimiento ─────────────────────────────────────────────────────
--list-modules        Listar todos los módulos disponibles con fuentes
--apis                Estado de todas las APIs configuradas (3 niveles)
--init-config         Generar config/config.yaml pre-rellenado
--health-check        Ver estado del health check de módulos
--reset-module ID     Resetear módulo marcado como deprecated
--db PATH             Ruta de base de datos (default: database/leviathan.db)
--reports-dir DIR     Directorio de reportes (default: reports/)
```

---

## 5. Variables de entorno

```bash
# Comportamiento global
LEVIATHAN_TOR=1              # Activar Tor (equivale a --tor)
LEVIATHAN_LLM=1              # Activar LLM (equivale a --llm)
K1_CONCURRENCY=10            # Requests concurrentes (default: 10)
LOG_LEVEL=DEBUG              # DEBUG | INFO | WARN | ERROR
OLLAMA_MODEL=phi3:mini       # Modelo LLM por defecto

# API Keys — todas opcionales, las más importantes primero
GITHUB_TOKEN=xxx             # GRATIS — sube el rate limit 80x (solo registro)
HIBP_API_KEY=xxx             # $3.50/mes — LA más importante para emails
SHODAN_API_KEY=xxx           # $49/año membership
HUNTER_API_KEY=xxx           # 25/mes gratis
IPINFO_TOKEN=xxx             # 50k req/mes gratis
NUMVERIFY_KEY=xxx            # 100/mes gratis
INTELX_KEY=xxx               # Darkweb / pastes
VIRUSTOTAL_KEY=xxx           # 500/día gratis
GREYNOISE_KEY=xxx            # Community free
SECURITYTRAILS_KEY=xxx       # 50/mes gratis
ABSTRACT_PHONE_KEY=xxx       # 250/mes gratis
ETHERSCAN_KEY=xxx            # Ethereum avanzado
DARKSEARCH_KEY=xxx           # Índice darkweb

# Ejemplos de uso combinado
LEVIATHAN_TOR=1 HIBP_API_KEY=mi_key python leviathan.py email@example.com
LEVIATHAN_LLM=1 python leviathan.py empresa.com --llm-model qwen2.5:32b
```

---

## 6. Dashboard TUI

### Rich TUI — Leviathan Abyss (por defecto)

```
╔══ 🐉 LEVIATHAN OSINT v4.0 ─────── 🎯 juan@gmail.com [EMAIL] ─── ⏱ 34s ══╗
╠══ ⚡ MÓDULOS ──────────────────────╦══ 🛡 ENTORNO ──────────────────────══╣
║ 09  UsernameEnum   ▓▓▓▒░  4.2s  ║ Tor: OFF   Proxy: N/A               ║
║ 17  LeaksPaste     ▓▓░░░  2.1s  ║ K1: ⚡ OK   K2: ⚡ OK   K3: ⚡ OK   ║
║ 21  DarkwebForum   ▓░░░░  1.0s  ║ ⚠ Riesgo: 67/100 [ALTO]             ║
║ ✔ PassiveDNS      4 ents  234ms ╠══ ⚙ MÉTRICAS ──────────────────────╣
║ ✔ WhoisRDAP       3 ents   89ms ║ Pending: 3  In-flight: 7            ║
╠══ 🔍 ENTIDADES (71) S/N=47% ──────║ Procesados: 52  Lat: ▁▂▃▄▃▂▁      ║
║ email  juan@gmail.com       92%  ║ S/N: ████████░░ 47%  Desc: 8       ║
║ breach RappiPay2023         95%  ╠══ 🔗 CORRELACIONES (4) ────────────╣
║ phone  +52 667 123 4567     88%  ║ ≡ email ↔ username       0.91     ║
║ domain jgarcia.dev          79%  ║ 💀 email ↔ breach         0.95     ║
╠══ 📋 HISTORIAL EN VIVO ─────────────────────────────────────────────╣
║ [11:26:14] ✔ LeaksPaste — 3 breaches — HIBP                          ║
║ [11:26:15] 🔗 email [leaked_in] RappiPay2023 — 95%                   ║
║ [11:26:16] ✔ ProfileComposite — narrativa generada                   ║
╠══ [1]Tor  [2]Export  [3]Grafo  [q]Salir ─────────────────────── q ══╣
```

**Activar:** por defecto (sin flags adicionales)

### Textual TUI — Avanzado (opt-in)

```bash
pip install textual
python leviathan.py target --textual
```

**Características adicionales sobre Rich:**
- Soporte completo de mouse (click, scroll, hover)
- Tabs navegables: Overview · Entities · Correlaciones · Log
- Scroll infinito en el log de eventos (hasta 1000 líneas)
- DataTable editable con sort por columna
- Hotkeys F1-F4 para cambiar de tab
- Resize dinámico de paneles

**Hotkeys Textual:**
```
F1 → Tab Overview      F2 → Tab Entities
F3 → Tab Correlaciones F4 → Tab Log completo
t  → Toggle Tor info   e  → Info Export
g  → Info Grafo        q  → Salir
```

---

## 7. Arquitectura del sistema

```
INPUT ──▶ Orchestrator v4.0
              │
              ├── Event Bus (pub/sub central asíncrono)
              │     Eventos: TARGET_STARTED, NEW_ENTITY, ENTITY_CONFIRMED,
              │              ENTITY_REJECTED, CORRELATION_FOUND, RISK_UPDATED,
              │              MODULE_STARTED, MODULE_DONE, MODULE_FAILED,
              │              GRAPH_UPDATED, PROFILE_UPDATED, SCAN_COMPLETE
              │
              ├── K1: Crawler (Python + curl_cffi opcional)
              │     ├─ Priority queue (min-heap por prioridad 1–10)
              │     ├─ Semaphore de concurrencia (default: 10)
              │     ├─ Token bucket por dominio (rate limiting)
              │     ├─ Smart Circuit Breaker módulo:dominio
              │     │   → 3 errores 403/429 = OPEN 1h → HALF_OPEN → CLOSED
              │     ├─ TLS fingerprinting (Chrome/Firefox/Safari/Edge/Linux)
              │     ├─ Human Mode (5 perfiles de delay: 0.2s–60s)
              │     ├─ Tor / Proxy Rotator con health check
              │     └─ Retry + backoff exponencial + jitter
              │
              │  emit(RawEntity) ──▶ Consensus Layer
              │                          │
              │                    Validators independientes (paralelo):
              │                    email_regex · email_disposable
              │                    email_mx_record · email_breach
              │                    phone_regex · phone_carrier
              │                    ip_format · ip_reputation
              │                    domain_format · domain_age
              │                    username_pattern · multi_source
              │                    + Freshness Bonus (×0.8–×1.5)
              │                    + Source Reputation (HIBP=1.8x, scrape=0.9x)
              │                    + Source Genealogy (penaliza upstream repetido)
              │                          │
              │                    EntityRecord
              │                    (verdict + confidence + votes + flags + explain())
              │                          │
              ├── K2: Correlator ◀────────┘
              │     ├─ 8 reglas de correlación automáticas
              │     ├─ Source Genealogy tracker
              │     ├─ Grafo NetworkX en memoria
              │     └─ emite CORRELATION_FOUND al bus
              │
              ├── K3: Storage
              │     ├─ SQLite WAL + FTS5 full-text + JSON1
              │     ├─ Escritura en batch (50 ops/flush)
              │     ├─ 8 tablas: targets, entities, entities_fts, correlations,
              │     │   module_results, module_health, learned_rules, audit_log
              │     └─ audit_log inmutable
              │
              ├── FastText Engine (background)
              │     ├─ Collector: acumula ejemplos de cada entidad confirmada
              │     ├─ Trainer: re-entrena cada 50 ejemplos nuevos
              │     ├─ Gold Dataset: 200 ejemplos × oversample 5x (ancla)
              │     └─ Classifier: entity_type, handle_class, content_relevance,
              │                    threat_relevance, region_hint
              │
              ├── SelfLearning (módulo 40)
              │     ├─ Analiza productividad de módulos por tipo de target
              │     ├─ Detecta y registra region hints (MX, US, ES, LATAM)
              │     ├─ Alimenta FastText con entidades confirmadas
              │     ├─ Alerta si tasa de descarte > 30%
              │     └─ Guarda reglas en learned_rules (SQLite)
              │
              ├── HealthChecker (background, delay 120s)
              │     ├─ Prueba módulos core contra targets de control
              │     ├─ 3 fallos consecutivos → DEPRECATED en SQLite
              │     └─ Orchestrator excluye deprecated automáticamente
              │
              ├── Plugin Manager
              │     ├─ Auto-discovery en plugins/*.py al arrancar
              │     ├─ Validación: MODULE_ID único, herencia correcta
              │     ├─ IDs 01-49 reservados para core, 50-99 para plugins
              │     └─ Plugins enqueued en K1 junto a módulos core
              │
              ├── ProfileCompositeBuilder (al finalizar)
              │     ├─ Pivot: entidad ≥0.75 confianza como nodo central
              │     ├─ Timeline cronológica de todos los eventos
              │     ├─ Ubicación por clustering de señales
              │     ├─ Behavioral tags neutros (observable, no inferido)
              │     └─ Narrativa automática en lenguaje natural
              │
              └── Advanced Pipeline (al finalizar)
                    ├─ RiskScoreEngine: 0-100, 10 factores ponderados
                    ├─ TimelineGenerator: cronología completa
                    ├─ AnomalyDetector: 7 detectores de inconsistencias
                    ├─ CrossRefValidator: validación cruzada multi-fuente
                    ├─ LLMSemanticAnalyzer: Ollama (si --llm activo)
                    ├─ RelationshipGraph: export GraphML + GEXF + D3.js HTML
                    └─ ExportReport: HTML completo + JSON
```

---

## 8. Los 41+ Módulos

### 🔍 Recon (8 módulos)

| ID | Módulo | Descripción | Fuentes principales |
|----|--------|-------------|---------------------|
| 01 | TargetSanitizer | Detecta y normaliza cualquier input (email, phone, domain, IP, username, person, crypto, plate, onion, URL) con regex MX/LATAM completa | Local |
| 02 | PassiveDNS | DNS lookup (A, MX, NS, PTR) + reverse DNS | HackerTarget |
| 03 | WhoisRDAP | WHOIS + RDAP estándar — extrae registrantes, emails, fechas | IANA RDAP, ARIN, RIPE, APNIC |
| 04 | IP2ASN | ASN, BGP prefix, org, geolocalización IP | BGPView, ipinfo.io |
| 05 | SubdomainEnum | Subdominios via Certificate Transparency logs | crt.sh, HackerTarget |
| 06 | PortsServices | Puertos abiertos, CVEs activos, hostnames | Shodan InternetDB (sin key) |
| 07 | TechFingerprint | Stack tecnológico (10 firmas) vía headers HTTP | HTTP directo |
| 08 | EmailPhoneHarvester | Emails y teléfonos del sitio web objetivo | Hunter.io, web scrape |

### 👤 People (11 módulos)

| ID | Módulo | Descripción | Fuentes principales |
|----|--------|-------------|---------------------|
| 09 | UsernameEnum | Username en 30+ plataformas en paralelo | HTTP async directo |
| 10 | SocialScrape | Metadata pública: nombre, email, org, ubicación | GitHub API, Telegram, Reddit JSON |
| 11 | PhotoReverse | Links de búsqueda inversa de avatar público | GitHub avatar → Google Lens, Yandex, TinEye, Bing |
| 12 | FamilyMapper | Organizaciones y seguidores (GitHub) | GitHub API |
| 13 | EmploymentHistory | Lenguajes primarios, repos, Keybase PGP | GitHub API, Keybase |
| 14 | EducationCerts | Afiliaciones académicas en publicaciones | Google Scholar |
| 15 | VehiclePlate | Placas MX + estado (30 prefijos) + REPUVE | REPUVE, DB ladas local |
| 16 | CriminalRecords | Solo listas públicas — INTERPOL Red Notices, OFAC SDN | INTERPOL API, OFAC API |
| 17 | LeaksPaste | Breaches email + reputación | HaveIBeenPwned, EmailRep.io |
| 18 | DarkwebLeakCorrelator | Pastes públicos que contengan el target | psbdmp.ws |
| 41 | EcommerceFootprint | Huella en e-commerce MX | MercadoLibre API, correlación breach Rappi |

### 🕸️ Darkweb (4 módulos)

| ID | Módulo | Descripción | Notas |
|----|--------|-------------|-------|
| 19 | DarkwebIntel | Índices .onion vía clearnet | Ahmia.fi |
| 20 | RansomwareIntel | Víctimas de grupos de ransomware | ransomware.live API pública |
| 21 | DarkwebForumMonitor | Threat Intel pasivo — índices públicos | DarkSearch API, IntelX — sin autenticación, sin interacción |
| 22 | BreachAggregator | Índices de breaches | BreachDirectory, Dehashed |

> **Módulo 21** — Monitoreo pasivo únicamente. Solo busca menciones del target en contenido público ya indexado. Sin login. Sin interacción con foros.

### 📡 Comms (6 módulos)

| ID | Módulo | Descripción | Fuentes |
|----|--------|-------------|---------|
| 26 | PhoneDeepOSINT | Carrier (Telcel/Movistar/AT&T), lada MX, ciudad | DB ladas 25 ciudades, Numverify, AbstractAPI |
| 27 | TelegramIntel | Perfil público, tipo de cuenta, suscriptores | t.me público, TGStat |
| 28 | CryptoWallet | BTC balance/txcount/cluster, ETH balance | blockchain.info, Etherscan, WalletExplorer |
| 30 | SIMSwapRisk | Evaluación heurística de riesgo SIM swap | Local + Numverify |
| 31 | VoIPDetection | Detecta números VoIP / virtuales | Rangos VoIP conocidos |
| 32 | MessengerFootprint | WhatsApp click-to-chat, Telegram por número | Click-to-chat público |

### 🧠 Advanced (9 módulos)

| ID | Módulo | Descripción | Notas |
|----|--------|-------------|-------|
| 33 | LLMSemanticAnalyzer | Análisis semántico con LLM local | Ollama — activar con --llm |
| 34 | RelationshipGraph | Export grafo GraphML + GEXF + HTML D3.js | networkx, pyvis |
| 35 | TimelineGenerator | Cronología completa de todos los eventos | De metadata de todas las entidades |
| 36 | RiskScoreEngine | Score 0-100 con 10 factores ponderados y explicación | Lee flags del Consensus |
| 37 | AnomalyDetector | 7 detectores de inconsistencias y anomalías | Cruce interno de entidades |
| 38 | CrossRefValidator | Validación cruzada multi-fuente | Distribución de verdicts, multi-source |
| 39 | ExportReport | Reportes HTML (theme Leviathan Abyss) + JSON | D3.js embebido, sin deps externas |
| 40 | SelfLearning | Aprende de cada scan, ajusta prioridades, alimenta FastText | SQLite learned_rules |
| 49 | MultiModalAnalyzer | EXIF metadata de imágenes públicas (opt-in) | Activar con --deep-multimodal |

### 🔌 Plugins (50+)

| ID | Módulo | Descripción |
|----|--------|-------------|
| 50 | HackerNewsSearch | Ejemplo incluido — búsqueda en HN API pública |
| 51+ | [tus plugins] | Auto-descubiertos desde plugins/*.py |

---

## 9. Consensus Engine

### Cómo funciona

Cada entidad emitida por un módulo pasa por validators independientes que votan. El engine combina los votos con pesos, penaliza conflictos, aplica freshness bonus y Source Reputation.

```
emit("email", "test@gmail.com", metadata={"breach_count": 3, "breach_date_months": 8})
    │
    ├── email_regex       → +0.30  w=1.0  → Formato válido. local=test tld=com
    ├── email_disposable  → +0.10  w=1.8  → gmail.com no está en lista negra
    ├── email_mx_record   → +0.30  w=1.2  → DNS MX existe y responde
    ├── email_breach      → +0.40  w=1.5  [freshness×1.2] → 3 breaches, 8 meses
    └── multi_source      → +0.10  w=0.6  → 2 fuentes independientes

    raw_score = Σ(score × weight × freshness) / Σ(weight) = 0.57
    conflict_penalty = 0.0 (no hay votos negativos)
    confidence = 0.30 + 0.57 - 0.0 = 0.87

    flags = [BREACH_HIT] → Critical Flag → boost a mín 0.65
    confidence final = 0.87 ≥ 0.80 → TRUSTED ✔
```

### Tabla de Verdicts

| Verdict | Confidence | Qué significa |
|---------|-----------|---------------|
| **TRUSTED** | ≥ 0.80 | Alta confianza, múltiples fuentes independientes |
| **LIKELY** | 0.60–0.79 | Probable, revisar flags antes de usar |
| **UNCERTAIN** | 0.40–0.59 | Datos insuficientes |
| **SUSPECT** | 0.25–0.39 | Señales negativas, tratar con cautela |
| **DISCARD** | < 0.25 | Descartado — no llega al Correlator |

### Freshness Bonus

| Antigüedad | Multiplicador |
|-----------|--------------|
| < 6 meses | ×1.5 |
| 6–18 meses | ×1.2 |
| 18–36 meses | ×1.0 |
| 3–5 años | ×0.9 |
| 5+ años | ×0.8 |

### Source Reputation

| Fuente | Peso |
|--------|------|
| HaveIBeenPwned | ×1.8 |
| Shodan | ×1.6 |
| IANA RDAP, BGPView | ×1.5 |
| Hunter.io, GitHub API | ×1.4 |
| EmailRep | ×1.3 |
| crt.sh, HackerTarget | ×1.1–1.2 |
| web_scrape | ×0.9 |
| photo_reverse | ×0.5 |

### Explainability

```python
record.explain()
# ENTIDAD: [email] test@gmail.com
# VEREDICTO: TRUSTED (confianza=87%)
# FUENTES: HaveIBeenPwned, EmailRep.io
# ──────────────────────────────────────
# VOTOS DE VALIDADORES:
#   email_regex            +0.30 (w=1.0)
#     → Formato válido. local=test tld=com
#   email_disposable       +0.10 (w=1.8)
#     → gmail.com no está en lista negra
#   email_mx_record        +0.30 (w=1.2)
#     → DNS MX existe y responde
#   email_breach           +0.40 (w=1.5) [freshness×1.2] [BREACH_HIT]
#     → Encontrado en 3 breach(es). Fecha: 8 meses atrás
#   multi_source           +0.10 (w=0.6)
#     → 2 fuentes independientes confirman
# FLAGS: BREACH_HIT
```

---

## 10. ProfileComposite

### El perfil que se cuenta solo

Cuando hay 3+ entidades vinculadas al mismo pivot (email/phone/username), el `ProfileCompositeBuilder` construye un perfil enriquecido con narrativa automática.

**Pivot:** entidad de alta confianza (≥0.75) como nodo central. Puede ser email, teléfono o username verificado en múltiples plataformas.

### Qué acumula

- **Identidad:** nombres reales, aliases en plataformas
- **Timeline:** eventos ordenados con fuente y confianza
- **Antigüedad digital:** primera mención encontrada, años de actividad
- **Plataformas:** GitHub, Telegram, Reddit, etc.
- **E-commerce:** plataformas de compra activas
- **Breaches:** nombre, fecha, data_classes, si hay credenciales expuestas
- **Ubicación:** clustering de señales (lada MX, IP geo, reviews, placas)
- **Behavioral tags neutrales:** basados en actividad observable pública

### Behavioral Tags (neutros, observacionales)

| Tag | Condición de detección |
|-----|------------------------|
| `developer_profile` | GitHub, GitLab, npm, PyPI, Docker activos |
| `online_shopper` | Amazon, MercadoLibre, Shopify activos |
| `messaging_apps` | Telegram, WhatsApp, Signal detectados |
| `crypto_user` | Wallet BTC/ETH con actividad |
| `long_digital_history` | 3+ breaches (implica presencia digital larga) |
| `uses_voip` | Número VoIP detectado |
| `darkweb_footprint` | Mención en contenido indexado darkweb |

---

## 11. FastText ML Local

### ¿Qué es y por qué?

FastText de Meta: clasificador de texto ultraligero. 100% offline. 2–5MB por modelo. Inferencia <1ms en CPU. Aprende de tu propio uso. Sin etiquetado manual. Sin GPU.

### Tasks del modelo

| Task | Etiquetas | Uso |
|------|-----------|-----|
| `entity_type` | email, phone, domain, ip, username, person, crypto... | Clasificar entidades ambiguas |
| `handle_class` | bot, real_person, corporate, anonymous | Para usernames y perfiles |
| `content_relevance` | relevant, noise, ambiguous | Para snippets darkweb/web |
| `threat_relevance` | threat, informational, noise | Para contenido de foros |
| `region_hint` | mx, us, es, latam, eu, other | Para módulos regionales |

### Cold Start

```
0 scans:    No opina. Devuelve neutro (0.5).
50 scans:   Empieza a tener forma.
100 scans:  Primeros modelos utilizables.
500 scans:  Confiable en producción.
```

### Gold Dataset — el ancla estadística

200 ejemplos perfectos incluidos. Se oversamplea ×5 en cada entrenamiento para que el modelo nunca se desvíe del "norte verdadero" aunque hayas investigado solo dominios por semanas.

### Comandos FastText

```bash
# Ver estado de todos los modelos
python leviathan.py --ft-status
#   entity_type      ✔ LISTO   512 muestras  2.3KB
#   handle_class     ✔ LISTO   380 muestras  1.8KB
#   content_relevance ⏳        60/100 muestras
#   threat_relevance  ⏳         0/60 muestras

# Forzar re-entrenamiento con datos actuales
python leviathan.py --ft-train

# Alimentar FastText desde reportes históricos
python leviathan.py --analyze-reports reports/

# Alimentar + entrenar
python leviathan.py --analyze-reports reports/ --ft-train
```

---

## 12. SelfLearning

El módulo 40 corre automáticamente al final de cada scan.

### Qué aprende

1. **Productividad de módulos** — qué módulos generan más entidades por segundo según el tipo de target. Los boost automáticamente para scans similares.

2. **Region hints** — target MX detectado → priorizar módulos 15 (placas), 26 (lada), 27 (Telegram MX) en el siguiente scan.

3. **Alimentación FastText** — cada entidad TRUSTED/LIKELY se convierte en ejemplo de entrenamiento. Automático, sin etiquetado manual.

4. **Alerta de ruido** — si el Consensus descarta >30% de entidades, genera advertencia visible en el TUI.

5. **Reglas guardadas en SQLite** — consultables directamente:
```sql
sqlite3 database/leviathan.db \
  "SELECT * FROM learned_rules ORDER BY confidence DESC;"
```

---

## 13. HealthCheck Background

Corre en background 2 minutos después del primer scan. No bloquea nada.

### Qué hace

Prueba módulos core contra targets de control (`google.com`, `torvalds` en GitHub, `8.8.8.8`). 3 fallos consecutivos → módulo marcado `DEPRECATED` → Orchestrator lo excluye automáticamente.

### Comandos

```bash
# Ver estado actual (solo lectura)
python leviathan.py --health-check

#   ID    MÓDULO                     STATUS         FALLOS  ENTS  MS    HORA
#   ──────────────────────────────────────────────────────────────────────────
#   02    PassiveDNS                 ✔ OK           0       4     234   11:30
#   05    SubdomainEnum              ✗ DEPRECATED   3       0     TIMEOUT
#   08    EmailPhoneHarvester        ⚠ FAIL 2/3     1       890   11:30

# Resetear módulo deprecated después de arreglarlo
python leviathan.py --health-check --reset-module 05
```

---

## 14. Plugin System

### Crear tu propio módulo

```bash
# 1. Copiar el template
cp plugins/example_plugin.py plugins/mi_modulo.py

# 2. Editar mi_modulo.py:
#    - Cambiar MODULE_ID (usar 50–99)
#    - Implementar _run(self, target)
#    - Usar self.emit() para output
#    - Usar self.get_json() / self.get_text() para HTTP

# 3. Verificar que se carga
python leviathan.py --list-plugins

# 4. Correr — se activa automáticamente
python leviathan.py target
```

### Template mínimo

```python
from leviathan.modules.base_module import BaseModule
from leviathan.core.models import Target, TargetType

class MiPlugin(BaseModule):
    MODULE_ID       = "51"          # 50-99 para plugins
    MODULE_NAME     = "MiPlugin"
    MODULE_PRIORITY = 7             # 7-9 recomendado
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["domain"]
    APPLICABLE      = {TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        data = await self.get_json(f"https://api.ejemplo.com/{target.normalized}")
        if data and data.get("resultado"):
            self.emit("domain", data["resultado"], {
                "fuente": "api_ejemplo",
            }, sources=["direct_scrape"])
```

### Reglas del Plugin System

- IDs **01–49**: reservados para módulos core de Leviathan
- IDs **50–99**: para tus plugins (usar `--list-plugins` para verificar colisiones)
- Heredar de `BaseModule` — obligatorio
- Usar `self.emit()` para todo output — obligatorio
- Usar `self.get_json()` / `self.get_text()` para HTTP — no usar `requests`
- No bloquear el event loop — todo `async/await`
- Si el plugin falla al cargar, Leviathan arranca igual sin él

---

## 15. Módulo 49 MultiModal (opt-in)

### Qué hace

Analiza **metadata** de imágenes públicas de perfiles:
- Extracción de EXIF completo (GPS, dispositivo, software, timestamp)
- Geolocalización desde coordenadas GPS en EXIF → emite location
- Generación de URLs de búsqueda inversa (Google Lens, Yandex, TinEye, Bing Visual)
- Detección de avatar en GitHub y Telegram (imágenes públicas)

### Qué NO hace

- ❌ No realiza reconocimiento facial biométrico
- ❌ No identifica personas por características físicas
- ❌ No almacena imágenes descargadas (procesadas en memoria, descartadas)

### Activación (requiere confirmación)

```bash
python leviathan.py target --deep-multimodal
# → Muestra aviso legal
# → Pide confirmación: ¿Confirmas que tienes autorización? [s/N]
# → Solo activa si respondes 's'
```

### Dependencias opcionales

```bash
pip install Pillow    # Para EXIF completo (sin PIL solo detecta presencia)
```

---

## 16. REST API

```bash
pip install fastapi uvicorn
python leviathan.py --api --port 8000
# Docs interactivas: http://localhost:8000/docs
```

### Endpoints completos

```bash
# Estado
GET  /                          → Página de bienvenida HTML

# Scans
POST /scan                      → Iniciar scan
     body: {"target": "...", "use_tor": false, "use_llm": false}
     → {"scan_id": "a1b2c3", "status": "running"}

GET  /scan/{scan_id}            → Estado del scan
GET  /entities/{scan_id}        → Entidades (filtros: verdict, type, min_confidence)
GET  /explain/{scan_id}/{value} → Explainability de una entidad
GET  /graph/{scan_id}           → Grafo (format: json|graphml|gexf|html)

# Batch
POST /batch                     → Múltiples targets
     body: {"targets": [...], "max_concurrent": 3}

# Info
GET  /modules                   → Lista de módulos disponibles
GET  /stats                     → Estadísticas globales
```

### Uso con curl

```bash
# Escanear
ID=$(curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"ejemplo.com"}' | python3 -c "
import sys,json; print(json.load(sys.stdin)['scan_id'])")

# Esperar y obtener entidades TRUSTED
sleep 30
curl "http://localhost:8000/entities/$ID?verdict=TRUSTED&min_confidence=0.8"

# Explainability
curl "http://localhost:8000/explain/$ID/admin@ejemplo.com"

# Descargar grafo HTML D3.js interactivo
curl "http://localhost:8000/graph/$ID?format=html" > grafo.html

# Descargar GraphML (para Maltego/Gephi)
curl "http://localhost:8000/graph/$ID?format=graphml" > grafo.graphml

# Batch
curl -X POST http://localhost:8000/batch \
  -H "Content-Type: application/json" \
  -d '{"targets":["a@a.com","b@b.com","c.com"],"max_concurrent":3}'
```

---

## 17. Batch Mode

```bash
# Archivo .txt — un target por línea
python leviathan.py --batch targets.txt

# Archivo .csv — toma primera columna
python leviathan.py --batch targets.csv

# Sin dashboard (servidores / CI)
python leviathan.py --batch targets.txt --no-tui

# Batch + Tor + LLM
python leviathan.py --batch targets.txt --tor --llm --no-tui

# Batch con output JSON
python leviathan.py --batch targets.txt --no-tui --output json > results.json
```

### Formato de archivo

```
# targets.txt — comentarios con #
usuario@empresa.com
+52 664 123 4567
empresa.com
8.8.8.8
mi_usuario
"Juan García López"
1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
```

---

## 18. Graph Export

El módulo 34 exporta en 4 formatos al final de cada scan:

| Formato | Uso | Cómo obtener |
|---------|-----|--------------|
| **HTML D3.js** | Browser — interactivo | Automático en reports/ |
| **GraphML** | Maltego, yEd, Gephi | Automático en reports/ |
| **GEXF** | Gephi (con colores por tipo) | Automático en reports/ |
| **JSON** | D3.js, Vis.js, scripts | API `/graph/{id}?format=json` |

El HTML interactivo incluye:
- Force-directed graph (D3.js v7 embebido, sin internet)
- Zoom, drag, pan, doble-click para fijar nodos
- Hover con información completa (verdict, confidence, flags)
- Colores por tipo de entidad (email=cyan, phone=verde, domain=purple...)
- Tamaño de nodo proporcional a confidence

---

## 19. Configuración de APIs

```bash
# Ver estado de todas las APIs
python leviathan.py --apis

# Generar config.yaml pre-rellenado con env vars actuales
python leviathan.py --init-config
```

### Nivel 0 — Sin key, siempre activo

Shodan InternetDB, crt.sh, HackerTarget, BGPView, ipinfo.io anónimo, IANA RDAP, GitHub anónimo (60/hora), ransomware.live, blockchain.info, Etherscan (5/seg), Ahmia.fi, INTERPOL Notices, EmailRep.io básico.

### Nivel 1 — Free tier (solo registro)

| API | Free tier | ENV | Por qué importa |
|-----|-----------|-----|-----------------|
| **GitHub Token** | 5,000 req/hora | `GITHUB_TOKEN` | **GRATIS** — sube 80x el rate limit |
| **ipinfo.io** | 50k req/mes | `IPINFO_TOKEN` | Geo completa + carrier + tipo IP |
| **Shodan** | 1 búsqueda/mes | `SHODAN_API_KEY` | Puertos, banners, historial |
| **Hunter.io** | 25/mes | `HUNTER_API_KEY` | Emails corporativos con nombre |
| **SecurityTrails** | 50/mes | `SECURITYTRAILS_KEY` | DNS histórico completo |
| **Numverify** | 100/mes | `NUMVERIFY_KEY` | Carrier, tipo línea, país |
| **IntelX** | Limitado | `INTELX_KEY` | Darkweb, pastes, leaks históricos |
| **VirusTotal** | 500/día | `VIRUSTOTAL_KEY` | Reputación IPs, dominios, URLs |
| **GreyNoise** | Community | `GREYNOISE_KEY` | ¿Es scanner? ¿Es malicioso? |
| **AbstractAPI Phone** | 250/mes | `ABSTRACT_PHONE_KEY` | Phone validation + carrier |
| **DarkSearch** | Limitado | `DARKSEARCH_KEY` | Índice darkweb clearnet |

### Nivel 2 — De pago (mayor calidad)

| API | Costo | Por qué vale |
|-----|-------|-------------|
| **HIBP** | $3.50/mes | La referencia de breaches. Sin alternativa real. |
| **Shodan Membership** | $49/año | Histórico, filtros avanzados, alertas. |
| **Dehashed** | Variable | Breach search avanzado con credenciales |

---

## 20. Configuración completa

```yaml
# config/config.yaml — generado con: python leviathan.py --init-config

leviathan:
  version: "4.0"
  db_path: "database/leviathan.db"
  reports_dir: "reports"
  logs_dir: "logs"

apis:
  github_token: ""              # GRATIS — solo necesitas cuenta GitHub
  hibp_key: ""                  # $3.50/mes — LA más importante
  shodan_key: ""                # $49/año
  hunter_key: ""                # 25/mes gratis
  ipinfo: ""                    # 50k/mes gratis
  intelx_key: ""
  virustotal_key: ""
  greynoise_key: ""
  securitytrails_key: ""
  numverify_key: ""
  abstract_phone_key: ""
  etherscan_key: ""
  darksearch_key: ""

tor:
  enabled: false
  socks_port: 9050
  new_circuit_on_rate_limit: true

proxy:
  enabled: false
  type: socks5                  # http | socks4 | socks5
  host: 127.0.0.1
  port: 1080
  fallback_direct: true
  proxy_list: []

llm:
  enabled: false
  backend: ollama
  host: http://localhost:11434
  model: phi3:mini              # phi3:mini | qwen2.5:32b | llama3.1:8b
  timeout: 120

kernels:
  crawler:
    max_concurrent_requests: 10
    human_mode: true
    jitter_factor: 0.3
  correlator:
    min_confidence_threshold: 0.4

fasttext:
  enabled: true
  retrain_every_n_examples: 50
  gold_dataset_oversample: 5

health_check:
  enabled: true
  delay_seconds: 120
  interval_hours: 24
  max_consecutive_failures: 3

plugins:
  enabled: true
  dir: plugins/
```

---

## 21. Source Genealogy

### El problema de la ilusión de verdad

Shodan + Censys + ZoomEye todas obtienen geolocalización de MaxMind. Si las tres "confirman" la misma IP como de México D.F., el Consensus podría darle 90% de confianza. En realidad es **la misma fuente repetida 3 veces**.

### La solución

```
Voto #1 via MaxMind (Shodan)   → ×1.0  (valor completo)
Voto #2 via MaxMind (Censys)   → ×0.5  (50% penalización)
Voto #3 via MaxMind (ZoomEye)  → ×0.2  (80% penalización)

DNS authoritative ≠ MaxMind ≠ HIBP → upstreams distintos → confianza real
```

### 40+ upstreams mapeados

`maxmind_geo`, `bgp_routing`, `iana_rdap`, `dns_authoritative`, `certificate_transparency`, `hibp_db`, `emailrep_db`, `breach_directory_db`, `pastebin_index`, `intelx_db`, `hunter_crawler`, `direct_scrape`, `github_api`, `telegram_direct`, `blockchain_info`, `etherscan_api`, `ransomware_live_db`, `ahmia_index`, `interpol_db`, `ofac_db`, `local_db`...

---

## 22. Executive Summary

Al final de cada scan se genera automáticamente en 5 secciones:

**Sin LLM** (siempre disponible, determinístico):
- Generado por reglas, 100% consistente con los datos del Consensus
- No inventa, no rellena, no alucina

**Con LLM** (`--llm`, requiere Ollama):
- System prompt estricto, temperatura 0.1
- Solo procesa entidades TRUSTED/LIKELY para evitar alucinaciones
- Máx 400 tokens de respuesta
- Incluye la sección determinística como fallback al final

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**1. IDENTIDAD / HUELLA CONFIRMADA**
   Juan García López, ubicación inferida: Culiacán, Sinaloa.
   Contacto: 2 emails, 1 teléfono. Plataformas: GitHub, Telegram, Reddit.

**2. HUELLA DIGITAL Y ANTIGÜEDAD**
   Primera actividad: 2019-08 (6 años de historial).
   2 breaches históricos detectados.
   E-commerce: MercadoLibre MX.

**3. FACTORES DE RIESGO CRÍTICO**
   [CRITICAL] Presencia en darkweb + datos comprometidos en breaches.
   2 entidad(es) encontradas en breaches de datos.
   Score: 67/100 [ALTO].

**4. CORRELACIONES CLAVE**
   juan@gmail.com [leaked_in] RappiPay2023 (95%)
   jgarcia667 [alias_of] juan.garcia.667 (85%)

**5. ANOMALÍAS DETECTADAS**
   DARKWEB_BREACH_CORRELATION: Presencia en darkweb + datos comprometidos
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 23. Seguridad operacional

### TLS Fingerprinting

Con `pip install curl_cffi`, cada request simula un browser diferente a nivel TLS (JA3 fingerprint real). El Circuit Breaker rota automáticamente al detectar bloqueos.

### Circuit Breaker inteligente

Por clave `módulo:dominio`:
- 3 errores 403/429 consecutivos → OPEN (1 hora, no hace requests)
- Después de 1h → HALF_OPEN (intenta una vez)
- Si funciona → CLOSED (operación normal)

### Human Mode (5 perfiles de delay)

```
45% → 0.2–1.0s   (clic rápido)
25% → 1.0–3.0s   (leyendo)
15% → 3.0–8.0s   (distracción leve)
10% → 8.0–20.0s  (pausa)
 5% → 20.0–60.0s (café / teléfono)
```

Headers con variación natural: Accept-Language rotativo, headers opcionales con 70% de probabilidad, orden de headers mezclado.

### Proxy Rotation

```yaml
proxy:
  enabled: true
  proxy_list:
    - "socks5://user:pass@proxy1:1080"
    - "socks5://user:pass@proxy2:1080"
    - "http://proxy3:8080"
```

Rotación automática por success_rate. Health check paralelo cada 30min. Fallback a directo si todos fallan (configurable).

---

## 24. Estructura del proyecto

```
leviathan/
├── leviathan.py                   # Entry point + CLI completo (14+ flags)
├── setup.py                       # Auto-setup y verificación
├── requirements.txt
├── README.md
│
├── core/
│   ├── models.py                  # Tipos de datos (Target, EntityRecord, etc.)
│   ├── event_bus.py               # Pub/sub central asíncrono
│   ├── consensus_engine.py        # Validators + Engine + Explainability
│   ├── orchestrator_v2.py         # Coordinador con FastText + SelfLearning + Plugins
│   ├── microkernel1_crawler.py    # K1: HTTP async + priority queue
│   ├── microkernel2_correlator.py # K2: 8 reglas + NetworkX
│   ├── microkernel3_storage.py    # K3: SQLite WAL + FTS5 + batch
│   ├── smart_request.py           # TLS + Circuit Breaker + Human Mode
│   ├── source_genealogy.py        # Anti-ilusión de verdad por upstream
│   ├── profile_composite.py       # Perfil automático + narrativa
│   ├── fasttext_engine.py         # ML local: Collector + Trainer + Classifier
│   ├── gold_dataset.py            # 200 ejemplos ancla para FastText
│   └── health_check.py            # Background health checker de módulos
│
├── modules/
│   ├── base_module.py             # Clase padre — solo emit()
│   ├── recon/
│   │   └── modules_01_08.py       # TargetSanitizer → EmailPhoneHarvester
│   ├── people/
│   │   └── modules_09_18.py       # UsernameEnum → DarkwebLeakCorrelator
│   ├── darkweb/
│   │   └── modules_19_32.py       # DarkwebIntel, Ransomware, Comms
│   └── advanced/
│       ├── modules_33_40.py       # Risk, Timeline, Anomaly, CrossRef, Report
│       ├── modules_33_41.py       # LLM, Graph, SelfLearning, Ecommerce
│       └── module_49_multimodal.py # EXIF metadata (opt-in --deep-multimodal)
│
├── plugins/
│   ├── __init__.py
│   ├── plugin_manager.py          # Auto-discovery + validación + carga
│   └── example_plugin.py          # Template + HackerNews de ejemplo
│
├── utils/
│   ├── dashboard.py               # Rich TUI — Leviathan Abyss (por defecto)
│   └── dashboard_textual.py       # Textual TUI (--textual, mouse + tabs)
│
├── api/
│   └── rest.py                    # FastAPI REST API completa
│
├── config/
│   ├── api_manager.py             # 3 niveles de APIs + status report
│   └── config.yaml                # Configuración principal
│
├── database/
│   ├── schema.sql                 # 8 tablas SQLite con FTS5
│   └── leviathan.db               # Generado en runtime
│
├── data/
│   └── fasttext/                  # Datos de entrenamiento FastText
│       ├── entity_type.txt
│       ├── handle_class.txt
│       ├── content_relevance.txt
│       ├── threat_relevance.txt
│       ├── region_hint.txt
│       └── models/                # Modelos .bin entrenados
│
├── reports/                       # HTML + JSON + GraphML + GEXF generados
└── logs/                          # Logs de sesión por fecha
```

---

## 25. Crear plugins

Ver sección 14 y el archivo `plugins/example_plugin.py` para el template completo.

**Resumen del ciclo:**
```
1. cp plugins/example_plugin.py plugins/mi_plugin.py
2. Editar MODULE_ID (50-99), MODULE_NAME, MODULE_PHASE
3. Implementar async def _run(self, target)
4. Usar self.emit() para output
5. python leviathan.py --list-plugins   ← verificar carga
6. python leviathan.py target            ← activo automáticamente
```

---

## 26. Roadmap v5.0

### Fase 1 — Kernels en Rust vía PyO3
K1 Crawler con reqwest+tokio, TLS real con boring-ssl, token bucket atómico.
K2 Correlator con petgraph + ahash. Fallback transparente a Python.

### Fase 2 — Graph Neural Network
Modelo GNN ligero (PyTorch Geometric o DGL) para predecir conexiones ocultas
en el grafo de correlaciones. Sin GPU requerido en inferencia.

### Fase 3 — Shadow Mode unificado
Flag `--shadow` que activa automáticamente: Tor + proxy list + TLS fingerprint aleatorio + human delays agresivos + circuit breaker reactivo.

### Fase 4 — Mobile First mejorado
Optimizaciones específicas para Termux/NetHunter: batería baja, RAM limitada,
modo offline con cache local, sync cuando hay conectividad.

### Fase 5 — Reporte PDF profesional
Export PDF con WeasyPrint o Playwright. "Executive Brief" de 1 página + "Full Dossier" de 10-20 páginas con timeline visual y grafo embebido.

---

## Créditos

**Creado por Luis Sánchez**

Framework OSINT diseñado con la filosofía de que la herramienta debe ser más inteligente con cada uso, pero siempre bajo control total del operador.

Arquitectura basada en: Event Bus, Microkernel pattern, Consensus voting, Source Genealogy anti-duplication, FastText local ML, Plugin system.

---

MIT License — uso libre para investigación y defensa.  
**Prohibido el uso ofensivo no autorizado.**

---

🐉 **Leviathan v4.0** — *"Si no tiene ≥2 fuentes que confirmen → descartar"*
