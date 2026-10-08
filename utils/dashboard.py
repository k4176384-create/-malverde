"""
Leviathan OSINT v4.0 — Dashboard TUI "Leviathan Abyss"
Rich panels · Catppuccin Mocha base · Abyss theme con bordes carmesí
5 fps · No desaparece al terminar · Sparklines de latencia
"""
from __future__ import annotations
import asyncio
import time
import logging
from collections import deque
from typing import Optional
from core.models import BusEvent, EventType

log = logging.getLogger("leviathan.dashboard")

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    log.warning("rich no instalado — modo texto plano")

# ─── Colores Leviathan Abyss ─────────────────────────────────────────────────
CLR_BG        = "#0A0A0A"
CLR_RED       = "#C8102E"
CLR_CYAN      = "#00F5FF"
CLR_PURPLE    = "#7B2FBE"
CLR_MUTED     = "#666677"
CLR_TEXT      = "#CDD6F4"   # Catppuccin Mocha text
CLR_GREEN     = "#A6E3A1"
CLR_YELLOW    = "#F9E2AF"
CLR_ORANGE    = "#FAB387"
CLR_ROSEWATER = "#F5E0DC"

VERDICT_COLOR = {
    "TRUSTED":   CLR_CYAN,
    "LIKELY":    CLR_PURPLE,
    "UNCERTAIN": CLR_MUTED,
    "SUSPECT":   CLR_ORANGE,
    "DISCARD":   CLR_RED,
}

RISK_COLOR = {
    "CRÍTICO": CLR_RED,
    "ALTO":    CLR_ORANGE,
    "MEDIO":   CLR_YELLOW,
    "BAJO":    CLR_GREEN,
    "NINGUNO": CLR_MUTED,
}

SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"

def sparkline(values: list[float], width: int = 16) -> str:
    if not values:
        return "─" * width
    recent = values[-width:]
    mn, mx = min(recent), max(recent)
    rng = mx - mn or 1
    chars = []
    for v in recent:
        idx = int((v - mn) / rng * (len(SPARKLINE_CHARS) - 1))
        chars.append(SPARKLINE_CHARS[idx])
    return "".join(chars)


class LeviathanlDashboard:
    """
    Dashboard TUI en tiempo real.
    Suscrito al Event Bus para actualización automática.
    """

    def __init__(self, target_raw: str = ""):
        self.target_raw    = target_raw
        self.target_type   = "UNKNOWN"
        self.scan_id       = ""
        self.started_at    = time.time()

        # Estado en tiempo real
        self.modules_running: dict[str, dict] = {}
        self.modules_done:    list[dict] = []
        self.entities_live:   list[dict] = []
        self.correlations:    list[dict] = []
        self.log_lines:       deque = deque(maxlen=25)
        self.latencies:       list[float] = []
        self.risk_score:      int = 0
        self.risk_level:      str = "NINGUNO"
        self.profile:         dict = {}

        # Métricas de queue
        self.pending    = 0
        self.inflight   = 0
        self.processed  = 0

        # Entropía de detección
        self.regex_hits     = 0
        self.consensus_hits = 0
        self.discarded      = 0

        # FastText predicciones simuladas (placeholder)
        self.ft_predictions: list[dict] = []

        # Control
        self._live: Optional[Live] = None
        self._running = False
        self._done    = False
        self._final_state: dict = {}

    async def on_event(self, event):
        if not hasattr(event, 'payload') or not hasattr(event, 'type'):
            return
        """Handler del Event Bus — actualiza estado interno."""
        p = event.payload
        t = event.type

        if t == EventType.TARGET_STARTED:
            self.target_raw  = p.get("target", self.target_raw)
            self.target_type = p.get("type", "UNKNOWN").upper()
            self.scan_id     = p.get("scan_id", "")
            self._log(f"[cyan]🎯 TARGET:[/] {self.target_raw} [{self.target_type}]")

        elif t == EventType.MODULE_STARTED:
            mid  = p.get("module_id", "?")
            name = p.get("module_name", "?")
            self.modules_running[mid] = {
                "id": mid, "name": name, "started": time.time()
            }
            self.inflight  = len(self.modules_running)
            self.pending   = max(0, self.pending - 1)
            self._log(f"[purple]⟶[/] {name} iniciado")

        elif t == EventType.MODULE_DONE:
            mid  = p.get("module_id", "?")
            name = p.get("module_name", "?")
            dur  = p.get("duration_ms", 0)
            ents = p.get("confirmed", 0)
            self.modules_running.pop(mid, None)
            self.modules_done.append({"id": mid, "name": name, "dur": dur, "ents": ents})
            self.inflight  = len(self.modules_running)
            self.processed += 1
            if dur > 0:
                self.latencies.append(dur)
            self._log(f"[green]✔[/] {name} — {ents} entidades — {dur:.0f}ms")

        elif t == EventType.MODULE_FAILED:
            mid  = p.get("module_id", "?")
            name = p.get("module_name", "?")
            err  = p.get("error", "error")
            self.modules_running.pop(mid, None)
            self.inflight = len(self.modules_running)
            self._log(f"[red]✗[/] {name} — {err[:50]}")

        elif t == EventType.ENTITY_CONFIRMED:
            self.consensus_hits += 1
            self.entities_live.append({
                "type":    p.get("type", "?"),
                "value":   p.get("value", "?")[:50],
                "verdict": p.get("verdict", "UNCERTAIN"),
                "conf":    p.get("confidence", 0),
                "flags":   p.get("flags", []),
            })
            if len(self.entities_live) > 100:
                self.entities_live = self.entities_live[-100:]

        elif t == EventType.ENTITY_REJECTED:
            self.discarded += 1

        elif t == EventType.CORRELATION_FOUND:
            self.correlations.append({
                "a":    p.get("entity_a", "?")[:35],
                "b":    p.get("entity_b", "?")[:35],
                "rel":  p.get("rel_type", "linked"),
                "conf": p.get("confidence", 0),
            })
            if len(self.correlations) > 30:
                self.correlations = self.correlations[-30:]
            self._log(f"[cyan]🔗[/] {p.get('entity_a','?')[:25]} [{p.get('rel_type','?')}] {p.get('entity_b','?')[:25]}")

        elif t == EventType.RISK_UPDATED:
            self.risk_score = p.get("risk_score", 0)
            self.risk_level = p.get("risk_level", "NINGUNO")

        elif t == EventType.PROFILE_UPDATED:
            self.profile = p.get("profile", {})

        elif t == EventType.SCAN_COMPLETE:
            self._done = True
            self._final_state = p
            self._log(f"[cyan]🏁 SCAN COMPLETO[/] — {p.get('entities',0)} entidades — {p.get('elapsed',0):.1f}s")

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_lines.append(f"[dim][{ts}][/] {msg}")

    # ─── Rich Layout ──────────────────────────────────────────────────────────

    def _make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header",  size=3),
            Layout(name="body",    ratio=1),
            Layout(name="footer",  size=3),
        )
        layout["body"].split_row(
            Layout(name="left",  ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["left"].split_column(
            Layout(name="modules",  ratio=2),
            Layout(name="entities", ratio=3),
        )
        layout["right"].split_column(
            Layout(name="env",     ratio=1),
            Layout(name="metrics", ratio=1),
            Layout(name="corr",    ratio=2),
            Layout(name="history", ratio=2),
        )
        return layout

    def _render_header(self) -> Panel:
        elapsed = time.time() - self.started_at
        title = Text()
        title.append("🐉 LEVIATHAN OSINT v4.0", style=f"bold {CLR_RED}")
        title.append("  ·  ", style=CLR_MUTED)
        title.append(f"🎯 {self.target_raw}", style=f"bold {CLR_CYAN}")
        title.append(f"  [{self.target_type}]", style=CLR_MUTED)
        title.append(f"  ·  ⏱ {elapsed:.0f}s", style=CLR_MUTED)
        return Panel(title, style=f"{CLR_RED}", box=box.HEAVY)

    def _render_modules(self) -> Panel:
        table = Table(box=None, padding=(0, 1), show_header=False)
        table.add_column("id",     width=4,  style=CLR_MUTED)
        table.add_column("name",   width=22)
        table.add_column("bar",    width=14)
        table.add_column("time",   width=7, style=CLR_MUTED)
        table.add_column("status", width=6)

        # Running
        for m in list(self.modules_running.values())[:8]:
            elapsed = time.time() - m["started"]
            bar     = "▓▓▓▒░" if elapsed < 5 else "▓▓▓▓▒"
            table.add_row(
                m["id"], m["name"], f"[{CLR_CYAN}]{bar}[/]",
                f"{elapsed:.1f}s", f"[{CLR_YELLOW}]⚡ RUN[/]"
            )

        # Done (last 6)
        for m in self.modules_done[-6:]:
            table.add_row(
                m["id"], m["name"],
                f"[{CLR_GREEN}]██████████[/]",
                f"{m['dur']:.0f}ms",
                f"[{CLR_GREEN}]✔[/] {m['ents']}"
            )

        return Panel(
            table,
            title=f"[{CLR_CYAN}]⚡ MÓDULOS  running={len(self.modules_running)} done={len(self.modules_done)}[/]",
            border_style=CLR_RED,
            box=box.SIMPLE_HEAD,
        )

    def _render_entities(self) -> Panel:
        table = Table(box=None, padding=(0, 1), show_header=True)
        table.add_column("TIPO",   width=10, style=CLR_MUTED)
        table.add_column("VALOR",  width=42)
        table.add_column("CONF",   width=6)
        table.add_column("VERDICT",width=10)

        recent = self.entities_live[-15:]
        for e in reversed(recent):
            vc = VERDICT_COLOR.get(e["verdict"], CLR_TEXT)
            flags_str = " ".join(f"[{CLR_RED}]{f}[/]" for f in e["flags"][:2])
            table.add_row(
                f"[{CLR_CYAN}]{e['type']}[/]",
                f"{e['value']} {flags_str}",
                f"[{vc}]{e['conf']:.0%}[/]",
                f"[{vc}]{e['verdict'][:7]}[/]",
            )

        total    = self.consensus_hits + self.discarded
        snr_pct  = int(self.consensus_hits / max(1, total) * 100)
        return Panel(
            table,
            title=f"[{CLR_CYAN}]🔍 ENTIDADES  total={total} S/N={snr_pct}%[/]",
            border_style=CLR_RED,
            box=box.SIMPLE_HEAD,
        )

    def _render_env(self) -> Panel:
        tor_status = f"[{CLR_GREEN}]ON[/]" if self.scan_id else f"[{CLR_MUTED}]OFF[/]"
        rc = RISK_COLOR.get(self.risk_level, CLR_MUTED)
        lines = [
            f"[{CLR_MUTED}]Tor:[/]   {tor_status}  [{CLR_MUTED}]Proxy:[/] [{CLR_MUTED}]N/A[/]",
            f"[{CLR_MUTED}]K1:[/]  [{CLR_GREEN}]⚡ OK[/]  [{CLR_MUTED}]K2:[/] [{CLR_GREEN}]⚡ OK[/]  [{CLR_MUTED}]K3:[/] [{CLR_GREEN}]⚡ OK[/]",
            f"[{CLR_MUTED}]Riesgo:[/] [{rc}]⚠ {self.risk_score}/100 [{self.risk_level}][/]",
        ]
        return Panel(
            "\n".join(lines),
            title=f"[{CLR_CYAN}]🛡 ENTORNO[/]",
            border_style=CLR_RED,
            box=box.SIMPLE_HEAD,
        )

    def _render_metrics(self) -> Panel:
        lat_spark = sparkline(self.latencies, 12)
        total = self.consensus_hits + self.discarded
        snr   = self.consensus_hits / max(1, total)
        bar_len = int(snr * 10)
        snr_bar = "█" * bar_len + "░" * (10 - bar_len)

        lines = [
            f"[{CLR_MUTED}]Pending:[/]  [{CLR_YELLOW}]{self.pending}[/]   [{CLR_MUTED}]In-flight:[/] [{CLR_CYAN}]{self.inflight}[/]",
            f"[{CLR_MUTED}]Procesados:[/] [{CLR_GREEN}]{self.processed}[/]",
            f"[{CLR_MUTED}]Lat:[/] [{CLR_CYAN}]{lat_spark}[/]",
            f"[{CLR_MUTED}]S/N:[/] [{CLR_GREEN}]{snr_bar}[/] {snr:.0%}",
            f"[{CLR_MUTED}]Descartadas:[/] [{CLR_RED}]{self.discarded}[/]  [{CLR_MUTED}]OK:[/] [{CLR_GREEN}]{self.consensus_hits}[/]",
        ]
        return Panel(
            "\n".join(lines),
            title=f"[{CLR_CYAN}]⚙ MÉTRICAS[/]",
            border_style=CLR_RED,
            box=box.SIMPLE_HEAD,
        )

    def _render_correlations(self) -> Panel:
        lines = []
        rel_icons = {
            "same_owner": "≡",
            "alias_of":   "≈",
            "linked":     "↔",
            "leaked_in":  "💀",
            "resolves_to": "→",
        }
        for c in self.correlations[-8:]:
            icon = rel_icons.get(c["rel"], "~")
            lines.append(
                f"[{CLR_CYAN}]{icon}[/] {c['a'][:22]} [{CLR_MUTED}]{c['rel'][:12]}[/] {c['b'][:22]} [{CLR_GREEN}]{c['conf']:.0%}[/]"
            )
        body = "\n".join(lines) if lines else f"[{CLR_MUTED}]Esperando correlaciones...[/]"
        return Panel(
            body,
            title=f"[{CLR_CYAN}]🔗 CORRELACIONES ({len(self.correlations)})[/]",
            border_style=CLR_RED,
            box=box.SIMPLE_HEAD,
        )

    def _render_history(self) -> Panel:
        lines = list(self.log_lines)[-12:]
        body  = "\n".join(lines) if lines else f"[{CLR_MUTED}]Iniciando...[/]"
        return Panel(
            body,
            title=f"[{CLR_CYAN}]📋 HISTORIAL EN VIVO[/]",
            border_style=CLR_RED,
            box=box.SIMPLE_HEAD,
        )

    def _render_footer(self) -> Panel:
        keys = "[1]Tor  [2]Export  [3]Grafo  [q]Salir"
        return Panel(
            f"[{CLR_MUTED}]{keys}[/]",
            style=CLR_RED,
            box=box.HEAVY,
        )

    def _update_layout(self, layout: Layout):
        layout["header"].update(self._render_header())
        layout["modules"].update(self._render_modules())
        layout["entities"].update(self._render_entities())
        layout["env"].update(self._render_env())
        layout["metrics"].update(self._render_metrics())
        layout["corr"].update(self._render_correlations())
        layout["history"].update(self._render_history())
        layout["footer"].update(self._render_footer())

    async def run(self, scan_coroutine):
        """
        Ejecutar el scan con el TUI en vivo.
        El dashboard no desaparece al terminar — muestra resumen final.
        """
        if not HAS_RICH:
            print("⚠ rich no instalado — ejecutando sin dashboard")
            result = await scan_coroutine
            return result

        console = Console()
        layout  = self._make_layout()
        self._running = True

        with Live(layout, console=console, refresh_per_second=5,
                  screen=True) as live:
            self._live = live

            # Correr scan en background
            scan_task = asyncio.create_task(scan_coroutine)

            while not scan_task.done():
                self._update_layout(layout)
                await asyncio.sleep(0.2)

            # Update final
            self._update_layout(layout)

        # Mostrar resumen final (sin borrar pantalla)
        result = scan_task.result()
        self._print_final_summary(console, result)
        return result

    def _print_final_summary(self, console, state):
        from rich.rule import Rule
        console.print()
        console.print(Rule(f"[{CLR_RED}]🐉 LEVIATHAN — SCAN COMPLETO[/]", style=CLR_RED))
        console.print(f"[{CLR_CYAN}]Target:[/]      {state.target.normalized}")
        console.print(f"[{CLR_CYAN}]Tipo:[/]        {state.target.type.value.upper()}")
        console.print(f"[{CLR_CYAN}]Entidades:[/]   {len(state.entities)} total / {len(state.trusted_entities())} confirmadas")
        console.print(f"[{CLR_CYAN}]Correlaciones:[/] {len(state.correlations)}")

        rc = RISK_COLOR.get(state.risk_level.value, CLR_MUTED)
        console.print(f"[{CLR_CYAN}]Riesgo:[/]      [{rc}]⚠ {state.risk_score}/100 [{state.risk_level.value}][/]")
        console.print(f"[{CLR_CYAN}]Tiempo:[/]      {state.elapsed():.1f}s")
        console.print(Rule(style=CLR_RED))

        if len(state.entities) == 0:
            console.print(f"\n[yellow]⚠ 0 entidades — posibles causas:[/]")
            console.print(f"  [dim]• Sin API keys configuradas (GITHUB_TOKEN, HIBP_API_KEY...)[/]")
            console.print(f"  [dim]• Sin conexión a internet[/]")
            console.print(f"  [dim]• Target sin presencia pública en las fuentes[/]")
            console.print(f"\n  [dim]Configurar: python leviathan.py --init-config[/]\n")

        # Mostrar top entidades
        if state.trusted_entities():
            console.print(f"\n[{CLR_CYAN}]Top entidades confirmadas:[/]")
            for e in sorted(state.trusted_entities(), key=lambda x: -x.confidence)[:8]:
                vc = VERDICT_COLOR.get(e.verdict.value, CLR_TEXT)
                console.print(f"  [{CLR_MUTED}]{e.type.value:<12}[/] [{vc}]{e.value:<50}[/] {e.confidence:.0%}")

        # Profile narrative si existe
        if self.profile and self.profile.get("narrative"):
            console.print(f"\n[{CLR_CYAN}]📋 Perfil:[/]")
            for line in self.profile["narrative"].splitlines():
                console.print(f"  {line}")

        console.print()
