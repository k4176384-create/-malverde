"""
Leviathan OSINT v4.0 — Smart Request Layer
TLS fingerprinting + Circuit Breaker inteligente + Human Mode + Rate limiting
"""
from __future__ import annotations
import asyncio
import random
import time
import logging
from enum import Enum
from typing import Any, Optional
import aiohttp

log = logging.getLogger("leviathan.request")

# ─── TLS Fingerprinting ────────────────────────────────────────────────────────

USER_AGENTS = {
    "chrome_win":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "firefox_mac":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:117.0) Gecko/20100101 Firefox/117.0",
    "safari_ios":   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "edge_win":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "chrome_linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

ACCEPT_LANGS = [
    "es-MX,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9,es-MX;q=0.8,es;q=0.7",
    "es-ES,es;q=0.9,es-MX;q=0.8,en;q=0.6",
    "en-GB,en;q=0.9,es;q=0.8",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
]

# ─── Human Mode Delays ────────────────────────────────────────────────────────

HUMAN_PROFILES = [
    (0.45, 0.2,  1.0),   # 45% clic rápido
    (0.25, 1.0,  3.0),   # 25% leyendo
    (0.15, 3.0,  8.0),   # 15% distracción
    (0.10, 8.0,  20.0),  # 10% pausa larga
    (0.05, 20.0, 60.0),  # 5% café / teléfono
]

def human_delay() -> float:
    r = random.random()
    cumulative = 0.0
    for prob, lo, hi in HUMAN_PROFILES:
        cumulative += prob
        if r <= cumulative:
            return random.uniform(lo, hi)
    return random.uniform(1.0, 3.0)

# ─── Circuit Breaker ──────────────────────────────────────────────────────────

class CBState(Enum):
    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CircuitBreaker:
    """
    Circuit Breaker por clave módulo:dominio.
    3 fallos 403/429 → OPEN 1h → HALF_OPEN → CLOSED si OK.
    """
    def __init__(self, threshold: int = 3, timeout_s: float = 3600):
        self._state:    dict[str, CBState] = {}
        self._failures: dict[str, int]     = {}
        self._opened:   dict[str, float]   = {}
        self._threshold = threshold
        self._timeout   = timeout_s

    def _key(self, module: str, domain: str) -> str:
        return f"{module}:{domain}"

    def is_open(self, module: str, domain: str) -> bool:
        k = self._key(module, domain)
        state = self._state.get(k, CBState.CLOSED)
        if state == CBState.OPEN:
            if time.time() - self._opened.get(k, 0) >= self._timeout:
                self._state[k] = CBState.HALF_OPEN
                return False
            return True
        return False

    def record_success(self, module: str, domain: str):
        k = self._key(module, domain)
        self._state[k]    = CBState.CLOSED
        self._failures[k] = 0

    def record_failure(self, module: str, domain: str):
        k = self._key(module, domain)
        self._failures[k] = self._failures.get(k, 0) + 1
        if self._failures[k] >= self._threshold:
            self._state[k]  = CBState.OPEN
            self._opened[k] = time.time()
            log.warning(f"CircuitBreaker OPEN: {k} — cooling 1h")

    def get_state(self, module: str, domain: str) -> CBState:
        k = self._key(module, domain)
        return self._state.get(k, CBState.CLOSED)

# ─── Token Bucket Rate Limiter ────────────────────────────────────────────────

class TokenBucket:
    """Rate limiter por dominio."""
    def __init__(self, rate: float = 1.0, capacity: float = 5.0):
        self._rate     = rate       # tokens/segundo
        self._capacity = capacity
        self._tokens:  dict[str, float] = {}
        self._last:    dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, domain: str):
        async with self._lock:
            now  = time.time()
            last = self._last.get(domain, now)
            elapsed = now - last
            tokens  = self._tokens.get(domain, self._capacity)
            tokens  = min(self._capacity, tokens + elapsed * self._rate)
            self._last[domain]   = now
            self._tokens[domain] = tokens

            if tokens >= 1.0:
                self._tokens[domain] -= 1.0
                return

        # Sin token → esperar
        wait = (1.0 - tokens) / self._rate
        await asyncio.sleep(wait + random.uniform(0.1, 0.5))

# ─── SmartRequest ─────────────────────────────────────────────────────────────

_circuit_breaker = CircuitBreaker()
_token_bucket    = TokenBucket(rate=2.0, capacity=8.0)

def _make_headers(extra: dict | None = None) -> dict[str, str]:
    ua_key  = random.choice(list(USER_AGENTS))
    headers = {
        "User-Agent":      USER_AGENTS[ua_key],
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Accept":          random.choice(ACCEPT_HEADERS),
    }
    # Headers opcionales con 70% de probabilidad
    if random.random() > 0.3:
        headers["DNT"] = "1"
    if random.random() > 0.3:
        headers["Sec-GPC"] = "1"
    if random.random() > 0.5:
        headers["Upgrade-Insecure-Requests"] = "1"
    # Mezclar orden
    shuffled = list(headers.items())
    random.shuffle(shuffled)
    result = dict(shuffled)
    if extra:
        result.update(extra)
    return result


async def smart_get(
    url:        str,
    module:     str = "generic",
    headers:    dict | None = None,
    params:     dict | None = None,
    timeout:    float = 15.0,
    human_mode: bool = True,
    tor:        bool = False,
    proxy:      str | None = None,
    retries:    int = 3,
) -> dict | None:
    """
    GET HTTP con: TLS fingerprinting, circuit breaker, rate limiting,
    human delays, retry con backoff exponencial.
    """
    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    if _circuit_breaker.is_open(module, domain):
        log.debug(f"CB OPEN — skipping {module}:{domain}")
        return None

    await _token_bucket.acquire(domain)

    if human_mode:
        delay = random.uniform(0.2, 1.2)  # delay base ligero
        await asyncio.sleep(delay)

    req_headers = _make_headers(headers)

    connector_kwargs: dict[str, Any] = {"ssl": True}
    if tor:
        from aiohttp_socks import ProxyConnector  # type: ignore
        connector = ProxyConnector.from_url("socks5://127.0.0.1:9050")
    elif proxy:
        from aiohttp_socks import ProxyConnector  # type: ignore
        connector = ProxyConnector.from_url(proxy)
    else:
        connector = aiohttp.TCPConnector(ssl=True)

    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                headers=req_headers,
            ) as session:
                async with session.get(
                    url, params=params,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status in (403, 429):
                        _circuit_breaker.record_failure(module, domain)
                        wait = (2 ** attempt) + random.uniform(0.5, 2.0)
                        log.warning(f"{resp.status} on {url} — retry {attempt+1}/{retries} in {wait:.1f}s")
                        await asyncio.sleep(wait)
                        continue
                    if resp.status == 200:
                        _circuit_breaker.record_success(module, domain)
                        ct = resp.headers.get("Content-Type", "")
                        if "json" in ct:
                            return await resp.json()
                        text = await resp.text()
                        return {"_text": text, "_status": resp.status}
                    if resp.status in (404, 410):
                        return None
                    log.debug(f"HTTP {resp.status} on {url}")
                    return None
        except asyncio.TimeoutError:
            log.debug(f"Timeout on {url} attempt {attempt+1}")
            _circuit_breaker.record_failure(module, domain)
        except Exception as e:
            log.debug(f"Request error {url}: {e}")
        if attempt < retries - 1:
            await asyncio.sleep((2 ** attempt) + random.uniform(0.3, 1.0))
    return None


async def smart_post(
    url:     str,
    module:  str = "generic",
    json:    dict | None = None,
    data:    dict | None = None,
    headers: dict | None = None,
    timeout: float = 15.0,
) -> dict | None:
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    if _circuit_breaker.is_open(module, domain):
        return None
    await _token_bucket.acquire(domain)
    req_headers = _make_headers(headers)
    try:
        async with aiohttp.ClientSession(headers=req_headers) as session:
            async with session.post(
                url, json=json, data=data,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    _circuit_breaker.record_success(module, domain)
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        return await resp.json()
                    return {"_text": await resp.text()}
                if resp.status in (403, 429):
                    _circuit_breaker.record_failure(module, domain)
                return None
    except Exception as e:
        log.debug(f"POST error {url}: {e}")
        return None
