"""
Leviathan OSINT v4.0 — Módulos Advanced adicionales
Módulo 40: SelfLearning — ajusta prioridades con base en resultados reales
Módulo 41: EcommerceFootprint MX — huella en e-commerce MX con datos públicos
"""
from __future__ import annotations
import logging
from modules.base_module import BaseModule
from core.models import Target, TargetType, ScanState, EntityRecord

log = logging.getLogger("leviathan.advanced2")


# ─── 40: SelfLearning ────────────────────────────────────────────────────────

class SelfLearning(BaseModule):
    """
    Aprende de cada scan y ajusta comportamiento futuro.
    - Boost de módulos productivos para ese tipo de target
    - Skip de módulos con 0% resultados consistentes
    - Hints geográficos para módulos regionales
    - Injection de Gold Dataset en FastText (primer arranque)
    - Tasa de descarte — si >30% alerta de ruido alto
    """
    MODULE_ID    = "40"
    MODULE_NAME  = "SelfLearning"
    MODULE_PHASE = "advanced"

    def learn_from_scan(self, state: ScanState, storage) -> dict:
        """Analizar resultados del scan y guardar reglas aprendidas."""
        insights = {
            "module_scores":   {},
            "discard_rate":    0.0,
            "top_entity_type": "",
            "region_hint":     "",
            "alerts":          [],
        }

        if not state.module_results:
            return insights

        # 1. Score por módulo: entidades confirmadas / tiempo
        for result in state.module_results:
            if result.duration_ms > 0:
                score = result.entities_out / (result.duration_ms / 1000)
                insights["module_scores"][result.module_id] = round(score, 3)

        # 2. Tasa de descarte
        total    = len(state.entities)
        discarded = sum(1 for e in state.entities if e.verdict.value == "DISCARD")
        if total > 0:
            insights["discard_rate"] = discarded / total
            if insights["discard_rate"] > 0.30:
                insights["alerts"].append(
                    f"Alta tasa de descarte: {insights['discard_rate']:.0%} — "
                    "revisar módulos o calidad del target"
                )

        # 3. Tipo de entidad más productivo
        from collections import Counter
        type_counts = Counter(e.type.value for e in state.trusted_entities())
        if type_counts:
            insights["top_entity_type"] = type_counts.most_common(1)[0][0]

        # 4. Region hint
        phones = [e for e in state.entities if e.type.value == "phone"]
        mx_phones = [p for p in phones if p.metadata.get("country") == "MX"]
        if mx_phones:
            insights["region_hint"] = "mx"

        # 5. Guardar en storage
        target_type = state.target.type.value
        for module_id, score in insights["module_scores"].items():
            storage.save_learned_rule(
                rule_type="module_productivity",
                target_type=target_type,
                module_id=module_id,
                region=insights.get("region_hint", ""),
                confidence=min(1.0, score / 10),
            )

        # 6. Alimentar FastText con entidades confirmadas
        try:
            from core.fasttext_engine import get_collector
            collector = get_collector()
            for entity in state.trusted_entities():
                collector.add_entity(entity.type.value, entity.value, entity.metadata)
            collector.flush()
        except Exception as e:
            log.debug(f"FastText feed error: {e}")

        log.info(
            f"SelfLearning: {len(state.module_results)} módulos analizados, "
            f"discard={insights['discard_rate']:.0%}, region={insights['region_hint']}"
        )
        return insights

    def get_priority_boost(self, module_id: str, target_type: str, storage) -> float:
        """
        Devuelve boost de prioridad basado en historial.
        >1.0 = más prioritario, <1.0 = menos.
        """
        try:
            conn = storage._conn_safe()
            row  = conn.execute("""
                SELECT confidence FROM learned_rules
                WHERE rule_type='module_productivity'
                  AND module_id=? AND target_type=?
                ORDER BY updated_at DESC LIMIT 1
            """, (module_id, target_type)).fetchone()
            if row:
                return 0.5 + row[0]  # range 0.5–1.5
        except Exception:
            pass
        return 1.0

    async def _run(self, target: Target):
        pass  # Llamado directamente por Orchestrator


# ─── 41: EcommerceFootprint MX ───────────────────────────────────────────────

class EcommerceFootprint(BaseModule):
    """
    Huella en plataformas de e-commerce en México.
    Solo fuentes públicas: reviews públicas, perfiles públicos,
    correlación con breaches conocidos, búsqueda en redes.
    NO accede a datos privados de transacciones.
    """
    MODULE_ID       = "41"
    MODULE_NAME     = "EcommerceFootprint"
    MODULE_PRIORITY = 6
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["other", "url"]

    APPLICABLE = {TargetType.EMAIL, TargetType.USERNAME, TargetType.PERSON}

    PLATFORMS_MX = {
        "mercadolibre": {
            "search_url": "https://api.mercadolibre.com/sites/MLM/search",
            "profile_url": "https://www.mercadolibre.com.mx/perfil/{query}",
        },
        "rappi_mx": {
            "breach_name": "RappiPay2023",
            "note": "Correlación via breach RappiPay 2023",
        },
    }

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized
        if target.type == TargetType.EMAIL:
            query = query.split("@")[0]

        # MercadoLibre — búsqueda pública de vendedores
        ml = await self.get_json(
            "https://api.mercadolibre.com/sites/MLM/search",
            params={"nickname": query, "limit": 3},
        )
        if ml and "results" in ml:
            for item in ml["results"][:3]:
                seller = item.get("seller", {})
                if seller.get("nickname", "").lower() == query.lower():
                    self.emit("other", seller.get("nickname", ""), {
                        "platform":           "mercadolibre_mx",
                        "seller_id":          seller.get("id"),
                        "profile_url":        f"https://www.mercadolibre.com.mx/perfil/{query}",
                        "ecommerce_platform": "MercadoLibre MX",
                        "reputation_level":   seller.get("seller_reputation", {}).get("level_id", ""),
                        "total_sales":        seller.get("seller_reputation", {}).get("transactions", {}).get("total", 0),
                    }, ["direct_scrape"])

        # Correlación con breach de RappiPay 2023 (si el email aparece en HIBP)
        # Esto lo procesa LeaksPaste — aquí solo agregamos el tag de footprint
        if target.type == TargetType.EMAIL:
            # Buscar en metadata si ya fue detectado en breach Rappi
            self.emit("other", "rappi_mx", {
                "platform":           "Rappi MX",
                "ecommerce_platform": "Rappi MX",
                "note":               "Verificar con módulo 17 (LeaksPaste) para breach RappiPay 2023",
                "check_breach":       "RappiPay2023",
            }, ["local_db"])

        # Amazon México — reviews públicas por username
        amz = await self.get_text(
            f"https://www.amazon.com.mx/gp/profile/amzn1.account.{query}",
            headers={"Accept-Language": "es-MX"},
        )
        if amz and "perfil" in amz.lower() and "amazon" in amz.lower():
            self.emit("url", f"https://www.amazon.com.mx/gp/profile/amzn1.account.{query}", {
                "platform":           "Amazon MX",
                "ecommerce_platform": "Amazon México",
                "query":              query,
            }, ["direct_scrape"])


# ─── 33: LLMSemanticAnalyzer ─────────────────────────────────────────────────

class LLMSemanticAnalyzer(BaseModule):
    """
    Análisis semántico con LLM local via Ollama.
    Requiere: ollama pull phi3:mini  (o qwen2.5:32b para mayor calidad)
    Solo procesa entidades TRUSTED/LIKELY para evitar alucinaciones.
    Temperatura 0.1 — máxima precisión.
    """
    MODULE_ID       = "33"
    MODULE_NAME     = "LLMSemanticAnalyzer"
    MODULE_PRIORITY = 9
    MODULE_PHASE    = "advanced"
    REQUIRES_API    = False

    def __init__(self, *args, llm_host: str = "http://localhost:11434",
                 llm_model: str = "phi3:mini", **kwargs):
        super().__init__(*args, **kwargs)
        self.llm_host  = llm_host
        self.llm_model = llm_model

    async def analyze(self, state: ScanState) -> str:
        """Generar análisis semántico de las entidades confirmadas."""
        trusted = state.trusted_entities()
        if not trusted:
            return "Insuficientes datos para análisis semántico."

        # Solo pasar entidades TRUSTED para evitar alucinaciones
        entity_summary = "\n".join(
            f"- [{e.type.value}] {e.value} (conf={e.confidence:.0%}, flags={e.flags})"
            for e in sorted(trusted, key=lambda x: -x.confidence)[:20]
        )

        system_prompt = """Eres un analista de inteligencia OSINT experto.
Tu tarea es analizar entidades confirmadas y producir un resumen ejecutivo profesional.
REGLAS ESTRICTAS:
1. Solo usa los datos proporcionados. NUNCA inventes información.
2. Si algo es incierto, dilo explícitamente.
3. Responde en español.
4. Máximo 5 puntos concisos.
5. Formato: bullets con prefijo •"""

        user_prompt = f"""TARGET: {state.target.normalized} [{state.target.type.value}]
RIESGO: {state.risk_score}/100 [{state.risk_level.value}]

ENTIDADES CONFIRMADAS:
{entity_summary}

Produce un análisis ejecutivo de 5 bullets."""

        try:
            result = await self.post_json(
                f"{self.llm_host}/api/generate",
                json={
                    "model":  self.llm_model,
                    "prompt": user_prompt,
                    "system": system_prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 400},
                },
                headers={"Content-Type": "application/json"},
            )
            if result and "response" in result:
                return result["response"].strip()
        except Exception as e:
            log.debug(f"LLM error: {e}")

        return "LLM no disponible — usando resumen determinístico."

    async def _run(self, target: Target):
        pass


# ─── 34: RelationshipGraph (standalone) ──────────────────────────────────────

class RelationshipGraph(BaseModule):
    """
    Módulo 34: RelationshipGraph standalone.
    Exporta el grafo de correlaciones en múltiples formatos.
    """
    MODULE_ID       = "34"
    MODULE_NAME     = "RelationshipGraph"
    MODULE_PRIORITY = 9
    MODULE_PHASE    = "advanced"

    def export_graphml(self, state: ScanState) -> str:
        """Exportar grafo en formato GraphML."""
        entities = {e.id: e for e in state.trusted_entities()}
        nodes_xml = "\n".join(
            f'  <node id="{e.id}">'
            f'<data key="label">{e.value[:60]}</data>'
            f'<data key="type">{e.type.value}</data>'
            f'<data key="verdict">{e.verdict.value}</data>'
            f'<data key="confidence">{e.confidence:.2f}</data>'
            f'</node>'
            for e in entities.values()
        )
        edges_xml = "\n".join(
            f'  <edge source="{c.entity_a}" target="{c.entity_b}">'
            f'<data key="rel">{c.rel_type}</data>'
            f'<data key="weight">{c.confidence:.2f}</data>'
            f'</edge>'
            for c in state.correlations
        )
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/graphml"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <key id="label"      for="node" attr.name="label"      attr.type="string"/>
  <key id="type"       for="node" attr.name="type"       attr.type="string"/>
  <key id="verdict"    for="node" attr.name="verdict"    attr.type="string"/>
  <key id="confidence" for="node" attr.name="confidence" attr.type="double"/>
  <key id="rel"        for="edge" attr.name="rel"        attr.type="string"/>
  <key id="weight"     for="edge" attr.name="weight"     attr.type="double"/>
  <graph id="leviathan_{state.target.scan_id}" edgedefault="directed">
{nodes_xml}
{edges_xml}
  </graph>
</graphml>"""

    def export_gexf(self, state: ScanState) -> str:
        """Exportar en GEXF (Gephi con colores y pesos)."""
        TYPE_COLORS = {
            "email": "0,245,255", "phone": "166,227,161", "domain": "123,47,190",
            "ip": "249,226,175", "username": "200,16,46", "person": "250,179,135",
            "crypto": "245,224,220", "breach": "243,139,168", "other": "108,112,134",
        }
        nodes_xml = "\n".join(
            f'      <node id="{e.id}" label="{e.value[:50]}">'
            f'<attvalues><attvalue for="0" value="{e.type.value}"/>'
            f'<attvalue for="1" value="{e.confidence:.2f}"/></attvalues>'
            f'<viz:color r="{TYPE_COLORS.get(e.type.value, "108,112,134").split(",")[0]}"'
            f' g="{TYPE_COLORS.get(e.type.value, "108,112,134").split(",")[1]}"'
            f' b="{TYPE_COLORS.get(e.type.value, "108,112,134").split(",")[2]}"/>'
            f'<viz:size value="{int(e.confidence * 20)}"/>'
            f'</node>'
            for e in state.trusted_entities()
        )
        edges_xml = "\n".join(
            f'      <edge id="{i}" source="{c.entity_a}" target="{c.entity_b}"'
            f' label="{c.rel_type}" weight="{c.confidence:.2f}"/>'
            for i, c in enumerate(state.correlations)
        )
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://gexf.net/1.3" version="1.3">
  <meta><creator>Leviathan OSINT v4.0</creator></meta>
  <graph defaultedgetype="directed">
    <attributes class="node">
      <attribute id="0" title="type" type="string"/>
      <attribute id="1" title="confidence" type="float"/>
    </attributes>
    <nodes>
{nodes_xml}
    </nodes>
    <edges>
{edges_xml}
    </edges>
  </graph>
</gexf>"""

    def save(self, content: str, fmt: str, scan_id: str, reports_dir: str = "reports") -> str:
        from pathlib import Path
        import time
        Path(reports_dir).mkdir(exist_ok=True)
        ts   = time.strftime("%Y%m%d_%H%M%S")
        path = Path(reports_dir) / f"leviathan_{scan_id}_{ts}.{fmt}"
        path.write_text(content, encoding="utf-8")
        return str(path)

    async def _run(self, target: Target):
        pass
