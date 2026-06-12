"""Командный интерфейс datashield.

Команды:
  redact     замаскировать текст (stdin/файл → stdout/файл)
  scan       показать найденные данные без маскировки
  stats      сводка по типам найденного
  detectors  список детекторов и их статус
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence

from datashield import __version__
from datashield.api import build_engine
from datashield.config import Config, load_config
from datashield.detectors.registry import build_catalog
from datashield.masking import mask_preview


def _read_input(path: Optional[str]) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    return sys.stdin.read()


def _write_output(path: Optional[str], text: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def _known_types(config: Config) -> set:
    return {info.detector.type for info in build_catalog(config)}


def _parse_types(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [item.strip().upper() for item in value.split(",") if item.strip()]


def _validate_types(types: Optional[List[str]], config: Config) -> Optional[str]:
    if not types:
        return None
    known = _known_types(config)
    unknown = [t for t in types if t not in known]
    if unknown:
        valid = ", ".join(sorted(known))
        return (
            f"Неизвестные типы: {', '.join(unknown)}.\nДоступные типы: {valid}"
        )
    return None


def _load_config_or_exit(path: Optional[str]) -> Config:
    try:
        return load_config(path)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"Ошибка конфигурации: {exc}\n")
        raise SystemExit(1)


def _cmd_redact(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(args.config)
    only = _parse_types(args.only)
    exclude = _parse_types(args.exclude)
    for problem in (_validate_types(only, config), _validate_types(exclude, config)):
        if problem:
            sys.stderr.write(problem + "\n")
            return 2
    engine = build_engine(
        config, min_confidence=args.min_confidence, only=only, exclude=exclude
    )
    text = _read_input(args.input)
    result = engine.redact(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            json.dump(result.report(), handle, ensure_ascii=False, indent=2)
    if args.json:
        payload = {
            "masked_text": result.masked_text,
            "stats": result.stats,
            "total": len(result.findings),
            "placeholders": result.placeholders,
        }
        _write_output(args.output, json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _write_output(args.output, result.masked_text)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(args.config)
    only = _parse_types(args.only)
    exclude = _parse_types(args.exclude)
    for problem in (_validate_types(only, config), _validate_types(exclude, config)):
        if problem:
            sys.stderr.write(problem + "\n")
            return 2
    engine = build_engine(
        config, min_confidence=args.min_confidence, only=only, exclude=exclude
    )
    findings = engine.analyze(_read_input(args.input))
    if args.json:
        payload = [
            {
                "type": f.type,
                "start": f.start,
                "end": f.end,
                "confidence": round(f.confidence, 3),
                "detector": f.detector,
                "preview": mask_preview(f.value),
            }
            for f in findings
        ]
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        return 0
    if not findings:
        sys.stdout.write("Конфиденциальных данных не найдено.\n")
        return 0
    sys.stdout.write(f"Найдено: {len(findings)}\n")
    for f in findings:
        sys.stdout.write(
            f"  [{f.type:<14}] поз. {f.start}-{f.end} "
            f"увер. {f.confidence:.2f}  {mask_preview(f.value)}  ({f.detector})\n"
        )
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(args.config)
    engine = build_engine(config, min_confidence=args.min_confidence)
    result = engine.redact(_read_input(args.input))
    if args.json:
        sys.stdout.write(json.dumps(result.stats, ensure_ascii=False, indent=2) + "\n")
        return 0
    if not result.stats:
        sys.stdout.write("Конфиденциальных данных не найдено.\n")
        return 0
    for type_name, count in sorted(result.stats.items()):
        sys.stdout.write(f"  {type_name:<16} {count}\n")
    sys.stdout.write(f"  {'ВСЕГО':<16} {len(result.findings)}\n")
    return 0


def _cmd_detectors(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(args.config)
    catalog = build_catalog(config)
    for info in catalog:
        status = "вкл " if info.enabled else "выкл"
        default = "" if info.default_enabled else "  (по умолчанию выкл)"
        sys.stdout.write(
            f"  [{status}] {info.detector.name:<18} -> {info.detector.type}{default}\n"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="datashield",
        description="Локальный фильтр приватности: маскирует конфиденциальные "
        "данные до отправки во внешний ИИ.",
    )
    parser.add_argument("--version", action="version", version=f"datashield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser, with_filters: bool = True) -> None:
        p.add_argument("-i", "--in", dest="input", help="входной файл (иначе stdin)")
        p.add_argument("-c", "--config", help="путь к .datashield.json")
        p.add_argument(
            "-m", "--min-confidence", type=float, default=None,
            help="порог уверенности (по умолчанию из конфига, 0.7)",
        )
        if with_filters:
            p.add_argument("--only", help="только эти типы (через запятую)")
            p.add_argument("--exclude", help="исключить эти типы (через запятую)")

    p_redact = sub.add_parser("redact", help="замаскировать текст")
    add_common(p_redact)
    p_redact.add_argument("-o", "--out", dest="output", help="выходной файл (иначе stdout)")
    p_redact.add_argument("--report", help="записать JSON-отчёт аудита (без сырых значений)")
    p_redact.add_argument("--json", action="store_true", help="вывод в JSON")
    p_redact.set_defaults(func=_cmd_redact)

    p_scan = sub.add_parser("scan", help="показать найденное без маскировки")
    add_common(p_scan)
    p_scan.add_argument("--json", action="store_true", help="вывод в JSON")
    p_scan.set_defaults(func=_cmd_scan)

    p_stats = sub.add_parser("stats", help="сводка по типам")
    add_common(p_stats, with_filters=False)
    p_stats.add_argument("--json", action="store_true", help="вывод в JSON")
    p_stats.set_defaults(func=_cmd_stats)

    p_det = sub.add_parser("detectors", help="список детекторов")
    p_det.add_argument("-c", "--config", help="путь к .datashield.json")
    p_det.set_defaults(func=_cmd_detectors)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except OSError as exc:
        sys.stderr.write(f"Ошибка ввода-вывода: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
