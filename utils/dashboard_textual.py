"""
Leviathan OSINT v4.0 — Dashboard Textual
pip install textual
python leviathan.py target --textual
"""
from __future__ import annotations
import asyncio
import time
import logging

log = logging.getLogger("leviathan.dashboard_textual")

try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, DataTable, Log, Label, Static
    from textual.containers import Horizontal, Vertical
    from textual.binding import Binding
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False


if HAS_TEXTUAL:

    CSS = """
    Screen { background: #0A0A0A; color: #CDD6F4; }
    Header { background: #C8102E; color: #FFFFFF; text-style: bold; height: 1; }
    Footer { background: #111111; color: #888888; height: 1; }
    #main-layout { height: 1fr; width: 100%; }
    #col-left  { width: 55%; height: 100%; border: solid #C8102E;   padding: 0 1; }
    #col-right { width: 45%; height: 100%; border: solid #333355;   padding: 0 1; }
    #tbl-modules  { height: 12; }
    #tbl-entities { height: 9; }
    #log-events   { height: 1fr; background: #050508; color: #8899AA; }
    #metrics      { height: 9;  border: solid #333355; padding: 0 1; }
    #corr-log     { height: 1fr; background: #030310; color: #A6E3A1; }
    .sec { color: #00F5FF; text-style: bold; height: 1; }
    DataTable > .datatable--header { background: #111122; color: #00F5FF; text-style: bold; }
    DataTable > .datatable--cursor { background: #1a1a2e; }
    """

    class LeviathanTextualApp(App):
        CSS = CSS
        BINDINGS = [
            Binding("q",  "quit",           "Salir"),
            Binding("f1", "focus_modules",  "Módulos"),
            Binding("f2", "focus_entities", "Entidades"),
            Binding("f3", "focus_corr",     "Correls"),
            Binding("f4", "focus_log",      "Log"),
        ]

        def __init__(self, target_raw: str = ""):
            super().__init__()
            self.target_raw   = target_raw
            self._start       = time.time()
            self._entities:   list[dict] = []
            self._risk_score  = 0
            self._risk_level  = "NINGUNO"
            self._scan_done   = False
            self._mod_count   = 0
            # Buffer de eventos que llegan antes de que el TUI esté listo
            self._event_queue: list = []
            self._mounted     = False

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="main-layout"):
                with Vertical(id="col-left"):
                    yield Label("⚡ MÓDULOS", classes="sec")
                    yield DataTable(id="tbl-modules")
                    yield Label("🔍 ENTIDADES", classes="sec")
                    yield DataTable(id="tbl-entities")
                    yield Label("📋 EVENTOS", classes="sec")
                    yield Log(id="log-events", max_lines=300)
                with Vertical(id="col-right"):
                    yield Label("⚙ MÉTRICAS", classes="sec")
                    yield Static("Iniciando...", id="metrics")
                    yield Label("🔗 CORRELACIONES", classes="sec")
                    yield Log(id="corr-log", max_lines=200)
            yield Footer()

        def on_mount(self) -> None:
            tm = self.query_one("#tbl-modules", DataTable)
            tm.add_columns("ID", "Módulo", "Estado", "Ents", "ms")

            te = self.query_one("#tbl-entities", DataTable)
            te.add_columns("Tipo", "Valor", "Conf", "Verdict")

            self.query_one("#log-events", Log).write_line(
                f"[{self._ts()}] 🐉 Leviathan v4.0 — {self.target_raw}"
            )
            self._mounted = True

            # Reproducir eventos que llegaron antes de montar
            for ev in self._event_queue:
                self._process_event(ev)
            self._event_queue.clear()

            self.set_interval(1.0, self._tick)

        def _ts(self) -> str:
            return time.strftime("%H:%M:%S")

        def _tick(self) -> None:
            elapsed = int(time.time() - self._start)
            total   = len(self._entities)
            ok      = sum(1 for e in self._entities if e.get("verdict") != "DISCARD")
            disc    = total - ok
            snr     = ok / max(1, total)
            bar     = "█" * int(snr * 10) + "░" * (10 - int(snr * 10))
            done    = "✔ COMPLETO" if self._scan_done else f"⏱ {elapsed}s"
            self.title = f"🐉 LEVIATHAN  {self.target_raw}  {done}"
            self.query_one("#metrics", Static).update(
                f"Target:    {self.target_raw}\n"
                f"Tiempo:    {elapsed}s  {'COMPLETO ✔' if self._scan_done else 'Ejecutando...'}\n"
                f"Módulos:   {self._mod_count}\n"
                f"Entidades: {total} total / {ok} confirmadas\n"
                f"S/N:       {bar} {snr:.0%}  Desc: {disc}\n"
                f"Riesgo:    {self._risk_score}/100 [{self._risk_level}]"
            )

        async def on_bus_event(self, event) -> None:
            """Llamado por el Event Bus de Leviathan."""
            if not hasattr(event, "payload") or not hasattr(event, "type"):
                return
            if not self._mounted:
                self._event_queue.append(event)
                return
            self._process_event(event)

        def _process_event(self, event) -> None:
            try:
                from core.models import EventType
            except Exception:
                return

            p  = event.payload
            et = event.type
            ts = self._ts()

            try:
                ev_log = self.query_one("#log-events", Log)
            except Exception:
                return

            if et == EventType.MODULE_STARTED:
                self._mod_count += 1
                mid  = p.get("module_id", "?")
                name = p.get("module_name", "?")
                try:
                    self.query_one("#tbl-modules", DataTable).add_row(
                        mid, name[:20], "⚡", "—", "—", key=f"m{mid}"
                    )
                except Exception:
                    pass
                ev_log.write_line(f"[{ts}] ⚡ {name}")

            elif et == EventType.MODULE_DONE:
                mid  = p.get("module_id", "?")
                name = p.get("module_name", "?")
                ents = p.get("confirmed", 0)
                ms   = int(p.get("duration_ms", 0))
                try:
                    tm = self.query_one("#tbl-modules", DataTable)
                    tm.update_cell(f"m{mid}", "Estado", "✔")
                    tm.update_cell(f"m{mid}", "Ents",   str(ents))
                    tm.update_cell(f"m{mid}", "ms",     str(ms))
                except Exception:
                    pass
                ev_log.write_line(f"[{ts}] ✔ {name} — {ents} ents {ms}ms")

            elif et == EventType.MODULE_FAILED:
                name = p.get("module_name", "?")
                mid  = p.get("module_id", "?")
                err  = p.get("error", "")[:35]
                ev_log.write_line(f"[{ts}] ✗ {name} — {err}")
                try:
                    self.query_one("#tbl-modules", DataTable).update_cell(f"m{mid}", "Estado", "✗")
                except Exception:
                    pass

            elif et == EventType.ENTITY_CONFIRMED:
                ent = {
                    "type":    p.get("type", "?"),
                    "value":   p.get("value", "?"),
                    "conf":    p.get("confidence", 0),
                    "verdict": p.get("verdict", "?"),
                }
                self._entities.append(ent)
                try:
                    self.query_one("#tbl-entities", DataTable).add_row(
                        ent["type"][:10],
                        ent["value"][:32],
                        f"{ent['conf']:.0%}",
                        ent["verdict"][:8],
                    )
                except Exception:
                    pass
                ev_log.write_line(
                    f"[{ts}] + [{ent['type']}] {ent['value'][:35]} ({ent['conf']:.0%})"
                )

            elif et == EventType.ENTITY_REJECTED:
                self._entities.append({"verdict": "DISCARD"})

            elif et == EventType.CORRELATION_FOUND:
                a    = p.get("entity_a", "?")[:22]
                b    = p.get("entity_b", "?")[:22]
                rel  = p.get("rel_type", "?")
                conf = p.get("confidence", 0)
                try:
                    self.query_one("#corr-log", Log).write_line(
                        f"[{ts}] {a} [{rel}] {b} ({conf:.0%})"
                    )
                except Exception:
                    pass
                ev_log.write_line(f"[{ts}] 🔗 {a} [{rel}] {b}")

            elif et == EventType.RISK_UPDATED:
                self._risk_score = p.get("risk_score", 0)
                self._risk_level = p.get("risk_level", "NINGUNO")

            elif et == EventType.SCAN_COMPLETE:
                self._scan_done = True
                elapsed = p.get("elapsed", 0)
                risk    = p.get("risk_score", 0)
                level   = p.get("risk_level", "")
                ev_log.write_line("─" * 44)
                ev_log.write_line(f"[{ts}] 🏁 SCAN COMPLETO — {elapsed:.1f}s")
                ev_log.write_line(f"     Entidades: {p.get('entities',0)} / Confirmadas: {p.get('trusted',0)}")
                ev_log.write_line(f"     Correlaciones: {p.get('correlations',0)}")
                ev_log.write_line(f"     Riesgo: {risk}/100 [{level}]")
                ev_log.write_line("─" * 44)
                self._tick()

        async def run_with_scan(self, scan_coroutine):
            result = {}

            async def _bg():
                try:
                    result["state"] = await scan_coroutine
                except Exception as e:
                    log.error(f"Scan error: {e}", exc_info=True)
                    result["error"] = e
                    try:
                        self.query_one("#log-events", Log).write_line(f"[ERROR] {e}")
                    except Exception:
                        pass
                finally:
                    await asyncio.sleep(2.0)
                    self.exit()

            asyncio.create_task(_bg())
            await self.run_async()
            if "error" in result:
                raise result["error"]
            return result.get("state")

        def action_quit(self):           self.exit()
        def action_focus_modules(self):  self.query_one("#tbl-modules",  DataTable).focus()
        def action_focus_entities(self): self.query_one("#tbl-entities", DataTable).focus()
        def action_focus_corr(self):     self.query_one("#corr-log",     Log).focus()
        def action_focus_log(self):      self.query_one("#log-events",   Log).focus()


# Stub cuando textual no está instalado
if not HAS_TEXTUAL:
    class LeviathanTextualApp:  # type: ignore
        def __init__(self, target_raw: str = ""):
            raise ImportError(
                "textual no instalado.\n"
                "Instalar: pip install textual\n"
                "O quitar --textual para el dashboard Rich."
            )
