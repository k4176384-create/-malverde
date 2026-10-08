"""
Leviathan OSINT v4.0 — REST API
FastAPI · Endpoints completos · Maltego Transform XML
"""
from __future__ import annotations
import asyncio
import json
import time
from typing import Optional
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from config.api_manager import APIManager
from core.orchestrator import Orchestrator
from core.models import ScanState

# Store de scans activos
_scans: dict[str, ScanState | str] = {}  # scan_id → ScanState | "running"


def create_app(api_manager: APIManager):
    if not HAS_FASTAPI:
        raise ImportError("fastapi no instalado. pip install fastapi uvicorn")

    app = FastAPI(
        title="🐉 Leviathan OSINT API v4.0",
        description="Framework OSINT. Solo para uso legal y autorizado.",
        version="4.0.0",
    )

    def get_orchestrator() -> Orchestrator:
        return Orchestrator(api_keys=api_manager.as_dict(), human_mode=True)

    # ─── Models ───────────────────────────────────────────────────────────────

    class ScanRequest(BaseModel):
        target:   str
        use_tor:  bool = False
        use_llm:  bool = False
        proxy:    Optional[str] = None

    class BatchRequest(BaseModel):
        targets:        list[str]
        max_concurrent: int = 3

    # ─── Endpoints ────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def root():
        return """<html><body style="background:#0A0A0A;color:#00F5FF;font-family:monospace;padding:40px">
        <h1>🐉 Leviathan OSINT API v4.0</h1>
        <p>Framework OSINT — solo para uso legal y autorizado.</p>
        <ul>
            <li><a href="/docs" style="color:#C8102E">📖 Documentación interactiva (Swagger)</a></li>
            <li><a href="/modules" style="color:#00F5FF">📋 Módulos disponibles</a></li>
            <li><a href="/stats" style="color:#00F5FF">📊 Estadísticas</a></li>
        </ul>
        </body></html>"""

    @app.post("/scan")
    async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        _scans[scan_id] = "running"

        async def _do_scan():
            orc = get_orchestrator()
            state = await orc.scan(req.target)
            state.target.scan_id = scan_id
            _scans[scan_id] = state

        background_tasks.add_task(_do_scan)
        return {"scan_id": scan_id, "status": "running", "target": req.target}

    @app.get("/scan/{scan_id}")
    async def get_scan(scan_id: str):
        result = _scans.get(scan_id)
        if result is None:
            raise HTTPException(404, "Scan no encontrado")
        if result == "running":
            return {"scan_id": scan_id, "status": "running"}

        state: ScanState = result
        return {
            "scan_id":      scan_id,
            "status":       "complete",
            "target":       state.target.normalized,
            "type":         state.target.type.value,
            "risk_score":   state.risk_score,
            "risk_level":   state.risk_level.value,
            "entities":     len(state.entities),
            "trusted":      len(state.trusted_entities()),
            "correlations": len(state.correlations),
            "elapsed":      state.elapsed(),
        }

    @app.get("/entities/{scan_id}")
    async def get_entities(
        scan_id: str,
        verdict: Optional[str] = None,
        type:    Optional[str] = None,
        min_confidence: float  = 0.0,
    ):
        result = _scans.get(scan_id)
        if not result or result == "running":
            raise HTTPException(404, "Scan no encontrado o en progreso")
        state: ScanState = result
        entities = state.entities
        if verdict:
            entities = [e for e in entities if e.verdict.value == verdict.upper()]
        if type:
            entities = [e for e in entities if e.type.value == type.lower()]
        if min_confidence > 0:
            entities = [e for e in entities if e.confidence >= min_confidence]
        return [
            {
                "id":         e.id,
                "type":       e.type.value,
                "value":      e.value,
                "confidence": e.confidence,
                "verdict":    e.verdict.value,
                "sources":    e.sources,
                "flags":      e.flags,
                "metadata":   e.metadata,
            }
            for e in sorted(entities, key=lambda x: -x.confidence)
        ]

    @app.get("/explain/{scan_id}/{entity_value}")
    async def explain_entity(scan_id: str, entity_value: str):
        result = _scans.get(scan_id)
        if not result or result == "running":
            raise HTTPException(404, "Scan no encontrado o en progreso")
        state: ScanState = result
        for e in state.entities:
            if e.value.lower() == entity_value.lower():
                return {"explanation": e.explain()}
        raise HTTPException(404, f"Entidad '{entity_value}' no encontrada")

    @app.get("/graph/{scan_id}")
    async def get_graph(scan_id: str, format: str = "json"):
        result = _scans.get(scan_id)
        if not result or result == "running":
            raise HTTPException(404, "Scan no encontrado o en progreso")
        state: ScanState = result

        nodes = [
            {"id": e.id, "label": e.value, "type": e.type.value,
             "verdict": e.verdict.value, "confidence": e.confidence}
            for e in state.trusted_entities()
        ]
        edges = [
            {"source": c.entity_a, "target": c.entity_b,
             "rel": c.rel_type, "weight": c.confidence}
            for c in state.correlations
        ]

        if format == "json":
            return {"nodes": nodes, "edges": edges}
        elif format == "graphml":
            xml_nodes = "\n".join(
                f'  <node id="{n["id"]}"><data key="label">{n["label"]}</data>'
                f'<data key="type">{n["type"]}</data></node>'
                for n in nodes
            )
            xml_edges = "\n".join(
                f'  <edge source="{e["source"]}" target="{e["target"]}">'
                f'<data key="rel">{e["rel"]}</data></edge>'
                for e in edges
            )
            graphml = f"""<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/graphml">
<graph id="leviathan" edgedefault="directed">
{xml_nodes}
{xml_edges}
</graph>
</graphml>"""
            from fastapi.responses import Response
            return Response(content=graphml, media_type="application/xml")
        elif format == "html":
            html = _build_graph_html(nodes, edges, scan_id)
            return HTMLResponse(html)
        else:
            raise HTTPException(400, "Formato no soportado: json|graphml|gexf|html")

    @app.post("/batch")
    async def run_batch(req: BatchRequest, background_tasks: BackgroundTasks):
        import uuid
        batch_id = str(uuid.uuid4())[:8]
        results  = {}
        sem      = asyncio.Semaphore(req.max_concurrent)

        async def _scan_one(target: str):
            async with sem:
                orc   = get_orchestrator()
                state = await orc.scan(target)
                results[target] = {
                    "risk_score": state.risk_score,
                    "risk_level": state.risk_level.value,
                    "entities":   len(state.entities),
                }

        async def _run_all():
            await asyncio.gather(*[_scan_one(t) for t in req.targets], return_exceptions=True)
            _scans[batch_id] = results  # type: ignore

        background_tasks.add_task(_run_all)
        return {"batch_id": batch_id, "targets": len(req.targets), "status": "running"}

    @app.get("/modules")
    async def get_modules():
        return {"modules": [
            {"id": "01", "phase": "recon",    "name": "TargetSanitizer"},
            {"id": "02", "phase": "recon",    "name": "PassiveDNS"},
            {"id": "03", "phase": "recon",    "name": "WhoisRDAP"},
            {"id": "04", "phase": "recon",    "name": "IP2ASN"},
            {"id": "05", "phase": "recon",    "name": "SubdomainEnum"},
            {"id": "06", "phase": "recon",    "name": "PortsServices"},
            {"id": "07", "phase": "recon",    "name": "TechFingerprint"},
            {"id": "08", "phase": "recon",    "name": "EmailPhoneHarvester"},
            {"id": "09", "phase": "people",   "name": "UsernameEnum"},
            {"id": "10", "phase": "people",   "name": "SocialScrape"},
            {"id": "11", "phase": "people",   "name": "PhotoReverse"},
            {"id": "12", "phase": "people",   "name": "FamilyMapper"},
            {"id": "13", "phase": "people",   "name": "EmploymentHistory"},
            {"id": "14", "phase": "people",   "name": "EducationCerts"},
            {"id": "15", "phase": "people",   "name": "VehiclePlate"},
            {"id": "16", "phase": "people",   "name": "CriminalRecords"},
            {"id": "17", "phase": "people",   "name": "LeaksPaste"},
            {"id": "18", "phase": "people",   "name": "DarkwebLeakCorrelator"},
            {"id": "19", "phase": "darkweb",  "name": "DarkwebIntel"},
            {"id": "20", "phase": "darkweb",  "name": "RansomwareIntel"},
            {"id": "21", "phase": "darkweb",  "name": "DarkwebForumMonitor"},
            {"id": "22", "phase": "darkweb",  "name": "BreachAggregator"},
            {"id": "26", "phase": "comms",    "name": "PhoneDeepOSINT"},
            {"id": "27", "phase": "comms",    "name": "TelegramIntel"},
            {"id": "28", "phase": "comms",    "name": "CryptoWallet"},
            {"id": "30", "phase": "comms",    "name": "SIMSwapRisk"},
            {"id": "31", "phase": "comms",    "name": "VoIPDetection"},
            {"id": "32", "phase": "comms",    "name": "MessengerFootprint"},
            {"id": "35", "phase": "advanced", "name": "TimelineGenerator"},
            {"id": "36", "phase": "advanced", "name": "RiskScoreEngine"},
            {"id": "37", "phase": "advanced", "name": "AnomalyDetector"},
            {"id": "38", "phase": "advanced", "name": "CrossRefValidator"},
            {"id": "39", "phase": "advanced", "name": "ExportReport"},
        ]}

    @app.get("/stats")
    async def get_stats():
        total_scans   = len([s for s in _scans.values() if s != "running"])
        running_scans = len([s for s in _scans.values() if s == "running"])
        return {
            "total_scans":   total_scans,
            "running_scans": running_scans,
            "api_version":   "4.0.0",
        }

    return app


def _build_graph_html(nodes: list, edges: list, scan_id: str) -> str:
    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Leviathan Graph — {scan_id}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
body {{ background: #0A0A0A; margin: 0; overflow: hidden; }}
svg {{ width: 100vw; height: 100vh; }}
.node circle {{ stroke: #00F5FF; stroke-width: 1.5; cursor: pointer; }}
.node text {{ fill: #CDD6F4; font: 10px monospace; pointer-events: none; }}
.link {{ stroke: #333355; stroke-opacity: 0.6; }}
.link-label {{ fill: #666677; font: 8px monospace; }}
#tooltip {{ position: absolute; background: #111; border: 1px solid #C8102E; color: #CDD6F4;
            padding: 8px 12px; font: 11px monospace; border-radius: 4px; pointer-events: none;
            display: none; max-width: 300px; }}
#info {{ position: absolute; top: 10px; left: 10px; color: #00F5FF; font: 12px monospace; }}
</style>
</head>
<body>
<div id="info">🐉 Leviathan Graph — Scan: {scan_id} | Nodes: {len(nodes)} | Edges: {len(edges)}</div>
<div id="tooltip"></div>
<svg></svg>
<script>
const nodes = {nodes_json};
const edges = {edges_json};
const typeColors = {{
  email: "#00F5FF", phone: "#A6E3A1", domain: "#7B2FBE",
  ip: "#F9E2AF", username: "#C8102E", person: "#FAB387",
  crypto: "#F5E0DC", breach: "#FF6666", other: "#666677",
}};

const svg   = d3.select("svg");
const w     = window.innerWidth;
const h     = window.innerHeight;
const g     = svg.append("g");
const tip   = document.getElementById("tooltip");

svg.call(d3.zoom().on("zoom", e => g.attr("transform", e.transform)));

const sim = d3.forceSimulation(nodes)
  .force("link",   d3.forceLink(edges).id(d => d.id).distance(100))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(w/2, h/2))
  .force("collision", d3.forceCollide(30));

const link = g.append("g").selectAll("line")
  .data(edges).join("line").attr("class", "link").attr("stroke-width", d => d.weight * 2 + 0.5);

const node = g.append("g").selectAll("g")
  .data(nodes).join("g").attr("class", "node")
  .call(d3.drag()
    .on("start", (e,d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on("drag",  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
    .on("end",   (e,d) => {{ if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }})
  );

node.append("circle")
  .attr("r", d => 8 + d.confidence * 6)
  .attr("fill", d => typeColors[d.type] || "#666")
  .attr("fill-opacity", 0.8)
  .on("mouseover", (e,d) => {{
    tip.style.display = "block";
    tip.style.left = (e.clientX + 12) + "px";
    tip.style.top  = (e.clientY - 10) + "px";
    tip.innerHTML = `<strong>[${{d.type}}]</strong> ${{d.label}}<br>Verdict: ${{d.verdict}}<br>Conf: ${{(d.confidence*100).toFixed(0)}}%`;
  }})
  .on("mousemove", e => {{ tip.style.left=(e.clientX+12)+"px"; tip.style.top=(e.clientY-10)+"px"; }})
  .on("mouseout", () => tip.style.display="none");

node.append("text")
  .attr("x", 12).attr("y", 4)
  .text(d => d.label.length > 28 ? d.label.slice(0,28)+"…" : d.label);

sim.on("tick", () => {{
  link.attr("x1", d=>d.source.x).attr("y1", d=>d.source.y)
      .attr("x2", d=>d.target.x).attr("y2", d=>d.target.y);
  node.attr("transform", d=>`translate(${{d.x}},${{d.y}})`);
}});
</script>
</body>
</html>"""
