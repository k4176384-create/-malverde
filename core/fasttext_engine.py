"""
Leviathan OSINT v4.0 — FastText Engine
ML local 100% offline. Sin GPU. Sin internet. Aprende de tu propio uso.
"""
from __future__ import annotations
import os
import logging
import tempfile
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("leviathan.fasttext")

try:
    import fasttext  # type: ignore
    HAS_FASTTEXT = True
except ImportError:
    try:
        import fasttext_wheel as fasttext  # type: ignore
        HAS_FASTTEXT = True
    except ImportError:
        HAS_FASTTEXT = False
        log.warning("fasttext no instalado — clasificación ML desactivada. pip install fasttext-wheel")

DATA_DIR = Path("data/fasttext")

# Tareas del modelo
TASKS = {
    "entity_type":       {"labels": ["email","phone","domain","ip","username","person","crypto","plate","onion","snippet","org","asn","cve","breach"], "min_samples": 100},
    "handle_class":      {"labels": ["bot","real_person","corporate","anonymous","researcher"], "min_samples": 80},
    "content_relevance": {"labels": ["relevant","noise","ambiguous"], "min_samples": 60},
    "threat_relevance":  {"labels": ["threat","informational","noise"], "min_samples": 60},
    "region_hint":       {"labels": ["mx","us","es","latam","eu","other"], "min_samples": 50},
}


class FastTextCollector:
    """Acumula ejemplos de entidades confirmadas."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._buffers: dict[str, list[str]] = {t: [] for t in TASKS}

    def add_entity(self, entity_type: str, value: str, metadata: dict):
        """Añadir ejemplo de entidad confirmada."""
        text = self._normalize(value)
        if not text:
            return

        # entity_type
        if entity_type in TASKS["entity_type"]["labels"]:
            self._buffers["entity_type"].append(f"__label__{entity_type} {text}")

        # handle_class — para usernames y personas
        if entity_type in ("username", "person"):
            hc = self._infer_handle_class(value, metadata)
            if hc:
                self._buffers["handle_class"].append(f"__label__{hc} {text}")

        # region_hint — para teléfonos y ubicaciones
        if entity_type == "phone":
            region = "mx" if metadata.get("country") == "MX" else "other"
            self._buffers["region_hint"].append(f"__label__{region} {text}")
        elif entity_type == "location":
            region = self._infer_region(value)
            self._buffers["region_hint"].append(f"__label__{region} {text}")

        # Flush automático
        if sum(len(b) for b in self._buffers.values()) >= 100:
            self.flush()

    def add_snippet(self, text: str, relevant: bool, threat: bool = False):
        """Añadir ejemplo de snippet de darkweb/web."""
        norm = self._normalize(text)
        if not norm:
            return
        rel_label = "relevant" if relevant else "noise"
        self._buffers["content_relevance"].append(f"__label__{rel_label} {norm}")
        thr_label = "threat" if threat else "informational"
        self._buffers["threat_relevance"].append(f"__label__{thr_label} {norm}")

    def flush(self):
        for task, lines in self._buffers.items():
            if not lines:
                continue
            path = DATA_DIR / f"{task}.txt"
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            self._buffers[task].clear()

    @staticmethod
    def _normalize(text: str) -> str:
        import re
        return re.sub(r'\s+', ' ', text.lower().strip())[:200]

    @staticmethod
    def _infer_handle_class(value: str, metadata: dict) -> Optional[str]:
        import re
        # Bot: muchos números, underscore+números, patrones repetitivos
        if re.match(r'^[a-z]+\d{4,}$', value.lower()):
            return "bot"
        if metadata.get("karma_post", 0) > 10000 and metadata.get("karma_comment", 0) < 100:
            return "bot"
        # Corporate: empresa en nombre
        if any(kw in value.lower() for kw in ["corp","inc","ltd","mx","official","news","support"]):
            return "corporate"
        # Real person: nombre + apellido pattern
        if re.match(r'^[a-z]+[._][a-z]+\d{0,2}$', value.lower()):
            return "real_person"
        return "anonymous"

    @staticmethod
    def _infer_region(location: str) -> str:
        loc = location.lower()
        mx_cities = ["méxico","ciudad de mexico","guadalajara","monterrey","tijuana","culiacan","cdmx","sinaloa","jalisco","nuevo leon"]
        us_cities = ["new york","los angeles","chicago","houston","phoenix","miami","california","texas"]
        if any(c in loc for c in mx_cities):
            return "mx"
        if any(c in loc for c in us_cities):
            return "us"
        if "spain" in loc or "españa" in loc or "madrid" in loc:
            return "es"
        return "other"


class FastTextTrainer:
    """Entrena modelos FastText con los datos acumulados."""

    def __init__(self, models_dir: Path = DATA_DIR / "models"):
        self.models_dir = models_dir
        self.models_dir.mkdir(parents=True, exist_ok=True)

    def train_all(self, force: bool = False) -> dict[str, bool]:
        """Entrenar todos los modelos que tienen suficientes datos."""
        results = {}
        for task, meta in TASKS.items():
            data_path = DATA_DIR / f"{task}.txt"
            if not data_path.exists():
                results[task] = False
                continue
            with open(data_path) as f:
                count = sum(1 for _ in f)
            if count < meta["min_samples"] and not force:
                log.debug(f"FastText {task}: {count}/{meta['min_samples']} muestras — skip")
                results[task] = False
                continue
            results[task] = self._train_one(task, data_path)
        return results

    def _train_one(self, task: str, data_path: Path) -> bool:
        if not HAS_FASTTEXT:
            return False
        try:
            # Inyectar Gold Dataset antes de entrenar
            from core.gold_dataset import GOLD_DATASET
            gold_lines = GOLD_DATASET.get(task, [])

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
                # Gold Dataset x5 (oversample)
                for _ in range(5):
                    tmp.write("\n".join(gold_lines) + "\n")
                # Datos reales
                with open(data_path, encoding="utf-8") as f:
                    tmp.write(f.read())
                tmp_path = tmp.name

            model = fasttext.train_supervised(
                input=tmp_path,
                epoch=25,
                lr=0.5,
                wordNgrams=2,
                minCount=1,
                verbose=0,
            )
            out_path = str(self.models_dir / f"{task}.bin")
            model.save_model(out_path)
            os.unlink(tmp_path)
            log.info(f"FastText {task} entrenado → {out_path}")
            return True
        except Exception as e:
            log.error(f"FastText train {task} error: {e}")
            return False


class FastTextClassifier:
    """Clasifica entidades usando los modelos entrenados."""

    def __init__(self, models_dir: Path = DATA_DIR / "models"):
        self.models_dir = models_dir
        self._models: dict[str, object] = {}
        self._load_all()

    def _load_all(self):
        if not HAS_FASTTEXT:
            return
        for task in TASKS:
            path = self.models_dir / f"{task}.bin"
            if path.exists():
                try:
                    self._models[task] = fasttext.load_model(str(path))
                    log.debug(f"FastText {task} cargado")
                except Exception as e:
                    log.debug(f"FastText {task} load error: {e}")

    def predict(self, task: str, text: str, k: int = 1) -> list[tuple[str, float]]:
        """
        Predice etiquetas para un texto.
        Devuelve lista de (label, confidence).
        Si el modelo no está entrenado, devuelve [(label_neutro, 0.5)].
        """
        if task not in self._models:
            return [(TASKS[task]["labels"][0], 0.5)]
        try:
            model = self._models[task]
            norm  = text.lower().strip().replace("\n", " ")[:200]
            labels, probs = model.predict(norm, k=k)
            return [
                (lbl.replace("__label__", ""), float(p))
                for lbl, p in zip(labels, probs)
            ]
        except Exception:
            return [(TASKS[task]["labels"][0], 0.5)]

    def predict_entity_type(self, value: str) -> tuple[str, float]:
        results = self.predict("entity_type", value)
        return results[0] if results else ("other", 0.5)

    def predict_handle_class(self, username: str) -> tuple[str, float]:
        results = self.predict("handle_class", username)
        return results[0] if results else ("anonymous", 0.5)

    def predict_content_relevance(self, snippet: str) -> tuple[str, float]:
        results = self.predict("content_relevance", snippet)
        return results[0] if results else ("noise", 0.5)

    def predict_region(self, text: str) -> tuple[str, float]:
        results = self.predict("region_hint", text)
        return results[0] if results else ("other", 0.5)

    def status(self) -> list[dict]:
        statuses = []
        for task, meta in TASKS.items():
            data_path = DATA_DIR / f"{task}.txt"
            model_path = self.models_dir / f"{task}.bin"
            sample_count = 0
            if data_path.exists():
                with open(data_path) as f:
                    sample_count = sum(1 for _ in f)
            statuses.append({
                "task":         task,
                "loaded":       task in self._models,
                "sample_count": sample_count,
                "min_needed":   meta["min_samples"],
                "model_size":   model_path.stat().st_size if model_path.exists() else 0,
                "ready":        sample_count >= meta["min_samples"],
            })
        return statuses


# ─── Singleton global ─────────────────────────────────────────────────────────
_collector:   Optional[FastTextCollector]   = None
_trainer:     Optional[FastTextTrainer]     = None
_classifier:  Optional[FastTextClassifier]  = None


def get_collector() -> FastTextCollector:
    global _collector
    if _collector is None:
        _collector = FastTextCollector()
    return _collector


def get_classifier() -> FastTextClassifier:
    global _classifier
    if _classifier is None:
        _classifier = FastTextClassifier()
    return _classifier


def get_trainer() -> FastTextTrainer:
    global _trainer
    if _trainer is None:
        _trainer = FastTextTrainer()
    return _trainer
