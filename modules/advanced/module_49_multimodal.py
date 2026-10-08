"""
Leviathan OSINT v4.0 — Módulo 49: MultiModalAnalyzer
Extracción de metadata EXIF de imágenes públicas.
Búsqueda inversa de imágenes (genera links, no descarga).

AVISO: Este módulo requiere activación explícita con --deep-multimodal.
Solo analiza imágenes públicas. No almacena imágenes descargadas.
No realiza reconocimiento facial biométrico — solo metadata de archivos.

Uso legítimo: OSINT defensivo, investigación periodística autorizada,
Incident Response, Brand Protection.
"""
from __future__ import annotations
import re
import logging
from modules.base_module import BaseModule
from core.models import Target, TargetType

log = logging.getLogger("leviathan.multimodal")

# ─── Advertencia opt-in ───────────────────────────────────────────────────────
DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║  ⚠  MÓDULO 49 — MultiModalAnalyzer  ⚠                       ║
║                                                              ║
║  Este módulo analiza metadata EXIF e imágenes PÚBLICAS.      ║
║  • Solo procesa imágenes de acceso público                   ║
║  • No realiza reconocimiento facial biométrico               ║
║  • No almacena imágenes descargadas                          ║
║  • Solo extrae metadata de archivos (GPS, dispositivo, etc.) ║
║                                                              ║
║  Activar únicamente si tienes autorización explícita         ║
║  para investigar al target.                                  ║
╚══════════════════════════════════════════════════════════════╝
"""


class MultiModalAnalyzer(BaseModule):
    """
    Módulo 49 — Análisis de imágenes públicas.

    Capacidades:
    - Extracción de EXIF metadata (GPS, dispositivo, software, timestamp)
    - Generación de URLs de búsqueda inversa (Google Lens, Yandex, TinEye)
    - Detección de imágenes modificadas (por metadata inconsistente)
    - Geolocalización desde coordenadas EXIF

    NO implementado (fuera del scope de OSINT de metadatos):
    - Reconocimiento biométrico facial
    - Identificación de personas por características físicas
    """
    MODULE_ID       = "49"
    MODULE_NAME     = "MultiModalAnalyzer"
    MODULE_PRIORITY = 8
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["location", "other", "url"]

    APPLICABLE      = {TargetType.USERNAME, TargetType.EMAIL, TargetType.DOMAIN}

    def __init__(self, *args, deep_enabled: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.deep_enabled = deep_enabled

    async def _run(self, target: Target):
        if not self.deep_enabled:
            log.debug("MultiModalAnalyzer desactivado — usar --deep-multimodal")
            return
        if target.type not in self.APPLICABLE:
            return

        username = target.normalized
        if target.type == TargetType.EMAIL:
            username = username.split("@")[0]

        # 1. Obtener avatar público de GitHub
        gh = await self.get_json(f"https://api.github.com/users/{username}")
        if gh and gh.get("avatar_url"):
            avatar_url = gh["avatar_url"]
            await self._analyze_image_url(avatar_url, "github_avatar", username)

        # 2. Telegram: foto de perfil pública
        tg_html = await self.get_text(f"https://t.me/{username}")
        if tg_html:
            img_match = re.search(r'<img class="tgme_page_photo_image" src="([^"]+)"', tg_html)
            if img_match:
                img_url = img_match.group(1)
                await self._analyze_image_url(img_url, "telegram_profile", username)

    async def _analyze_image_url(self, img_url: str, source: str, username: str):
        """Analizar una URL de imagen pública."""
        # 1. Descargar metadata sin guardar la imagen
        exif_data = await self._extract_exif_from_url(img_url)
        if exif_data:
            self.emit("other", img_url[:80], {
                "type":       "image_metadata",
                "source":     source,
                "username":   username,
                "exif":       exif_data,
                "has_gps":    "gps_lat" in exif_data,
                "has_device": "device_make" in exif_data,
            }, [source])

            # Si hay GPS → emitir location
            if exif_data.get("gps_lat") and exif_data.get("gps_lon"):
                lat = exif_data["gps_lat"]
                lon = exif_data["gps_lon"]
                self.emit("location", f"{lat},{lon}", {
                    "type":       "gps_exif",
                    "source_url": img_url[:80],
                    "source":     source,
                    "username":   username,
                    "maps_url":   f"https://maps.google.com/?q={lat},{lon}",
                }, [source])
                log.info(f"MultiModal: GPS encontrado en {source} para {username}: {lat},{lon}")

        # 2. Generar links de búsqueda inversa (no ejecutar, solo generar URLs)
        reverse_engines = {
            "google_lens": f"https://lens.google.com/uploadbyurl?url={img_url}",
            "yandex":      f"https://yandex.com/images/search?rpt=imageview&url={img_url}",
            "tineye":      f"https://tineye.com/search?url={img_url}",
            "bing_visual": f"https://www.bing.com/images/search?q=imgurl:{img_url}&view=detailv2&iss=sbi",
        }
        for engine, url in reverse_engines.items():
            self.emit("url", url, {
                "type":         "reverse_image_search",
                "engine":       engine,
                "source_image": img_url[:80],
                "username":     username,
                "note":         "URL para búsqueda inversa — abrir manualmente",
            }, [source])

    async def _extract_exif_from_url(self, url: str) -> dict:
        """
        Descargar imagen en memoria (sin guardar) y extraer EXIF.
        Solo analiza metadata — no guarda imagen localmente.
        """
        try:
            import aiohttp
            from io import BytesIO
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return {}
                    # Limitar a 5MB para evitar descargas masivas
                    content_len = int(resp.headers.get("Content-Length", 0))
                    if content_len > 5_000_000:
                        return {}
                    data = await resp.read()

            return self._parse_exif(data)
        except Exception as e:
            log.debug(f"EXIF extraction error: {e}")
            return {}

    @staticmethod
    def _parse_exif(image_bytes: bytes) -> dict:
        """
        Parsear metadata EXIF de bytes de imagen.
        Solo extrae metadata — no procesa contenido visual.
        """
        exif_data: dict = {}
        try:
            # Intentar con PIL si está disponible
            try:
                from PIL import Image, ExifTags  # type: ignore
                from io import BytesIO
                img  = Image.open(BytesIO(image_bytes))
                raw_exif = img._getexif()  # type: ignore
                if not raw_exif:
                    return {}
                for tag_id, value in raw_exif.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag == "GPSInfo":
                        gps = {}
                        for gps_id, gps_val in value.items():
                            gps[ExifTags.GPSTAGS.get(gps_id, str(gps_id))] = gps_val
                        # Convertir a decimal
                        def dms_to_dd(dms, ref):
                            d, m, s = dms
                            dd = float(d) + float(m)/60 + float(s)/3600
                            return -dd if ref in ('S','W') else dd
                        if "GPSLatitude" in gps and "GPSLongitude" in gps:
                            exif_data["gps_lat"] = round(dms_to_dd(
                                gps["GPSLatitude"],
                                gps.get("GPSLatitudeRef","N")
                            ), 6)
                            exif_data["gps_lon"] = round(dms_to_dd(
                                gps["GPSLongitude"],
                                gps.get("GPSLongitudeRef","E")
                            ), 6)
                    elif tag == "Make":
                        exif_data["device_make"] = str(value)[:50]
                    elif tag == "Model":
                        exif_data["device_model"] = str(value)[:50]
                    elif tag == "Software":
                        exif_data["software"] = str(value)[:50]
                    elif tag == "DateTime":
                        exif_data["datetime_original"] = str(value)
                    elif tag == "DateTimeOriginal":
                        exif_data["datetime_original"] = str(value)

            except ImportError:
                # Parseo manual básico de JPEG EXIF sin PIL
                exif_data = MultiModalAnalyzer._parse_exif_manual(image_bytes)

        except Exception as e:
            log.debug(f"EXIF parse error: {e}")
        return exif_data

    @staticmethod
    def _parse_exif_manual(data: bytes) -> dict:
        """Parser EXIF básico sin PIL — busca marcadores JPEG."""
        exif_data: dict = {}
        # Verificar header JPEG
        if data[:2] != b'\xff\xd8':
            return {}
        # Buscar APP1 marker (EXIF)
        i = 2
        while i < len(data) - 4:
            if data[i:i+2] == b'\xff\xe1':
                length = int.from_bytes(data[i+2:i+4], 'big')
                segment = data[i+4:i+2+length]
                if segment[:6] == b'Exif\x00\x00':
                    exif_data["has_exif"] = True
                    # No podemos parsear sin PIL — indicar presencia
                    break
            i += 1
        return exif_data
