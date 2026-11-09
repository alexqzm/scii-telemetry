"""Общие функции: пути, правила, конвейер полей, наборы событий."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
#: наборы событий: сценарии стенда cps-update-lab и дополнительные случаи labcases/cases.py
DATASETS = {
    "cpslab": ROOT / "dataset" / "cpslab-0.1.0",
    "cases": ROOT / "dataset" / "cases-0.1.0",
}
#: синтетические события для правил, которых стенд не касается (с описанием в поле _test)
SYNTHETIC = ROOT / "tests" / "events" / "synthetic.jsonl"
CONVERSIONS = ROOT / "conversions"
PIPELINE = ROOT / "pipelines" / "scii-telemetry.yml"
MAPPINGS = ROOT / "mappings" / "mappings.yml"
EXPECTED = ROOT / "tests" / "expected_matrix.yml"

#: ключ синтетического события с описанием случая; в журнал не попадает
TEST_KEY = "_test"


@lru_cache(maxsize=1)
def pipeline_yaml() -> str:
    return PIPELINE.read_text(encoding="utf-8")


def pipeline() -> ProcessingPipeline:
    """Новый экземпляр конвейера: бэкенд меняет его состояние при конвертации."""
    return ProcessingPipeline.from_yaml(pipeline_yaml())


@dataclass
class RuleFile:
    path: Path
    collection: SigmaCollection

    @property
    def key(self) -> str:
        return self.path.stem

    @property
    def rel(self) -> str:
        return self.path.relative_to(ROOT).as_posix()

    @property
    def correlation(self) -> SigmaCorrelationRule | None:
        for rule in self.collection.rules:
            if isinstance(rule, SigmaCorrelationRule):
                return rule
        return None

    @property
    def base_rules(self) -> list[SigmaRule]:
        return [r for r in self.collection.rules if isinstance(r, SigmaRule)]

    @property
    def primary(self) -> SigmaRule | SigmaCorrelationRule:
        return self.correlation or self.base_rules[0]

    @property
    def services(self) -> set[str]:
        return {r.logsource.service for r in self.base_rules}


def load_rule_file(path: Path, text: str | None = None) -> RuleFile:
    collection = SigmaCollection.from_yaml(text if text is not None else path.read_text(encoding="utf-8"))
    collection.resolve_rule_references()
    return RuleFile(path, collection)


def rule_files(root: Path = RULES) -> list[RuleFile]:
    return [load_rule_file(p) for p in sorted(root.rglob("*.yml"))]


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


def dataset_events(name: str) -> list[dict]:
    return load_jsonl(DATASETS[name] / "events.jsonl")


def strip_test(event: dict) -> dict:
    return {k: v for k, v in event.items() if k != TEST_KEY}


def flatten(event: dict, prefix: str = "") -> dict:
    """{"event": {"action": x}} → {"event.action": x}; списки остаются значениями."""
    out = {}
    for key, value in event.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, name + "."))
        else:
            out[name] = value
    return out


def get(event: dict, dotted: str):
    node = event
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def load_mappings() -> dict:
    return yaml.safe_load(MAPPINGS.read_text(encoding="utf-8"))
