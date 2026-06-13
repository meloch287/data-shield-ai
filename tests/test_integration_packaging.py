"""Статическая распайка интеграций и упаковки Data Shield AI.

Проверяем, что репозиторий действительно «склеен» так, как описано в Block G:

* .pre-commit-hooks.yaml — список хуков с id "data-shield-ai" и entry "datashield check";
* action.yml — composite-экшен GitHub с inputs paths/min-severity;
* pyproject.toml — [project.scripts] datashield + datashield-mcp, в пакетах есть
  datashield.integrations;
* пакет datashield.integrations импортируется без ошибок (mcp_server / http_server /
  logging_filter).

Никаких сторонних зависимостей: pyyaml НЕ импортируем (YAML проверяем по тексту и
минимальным разбором), TOML читаем через stdlib tomllib, который есть на 3.11+.
"""
from __future__ import annotations

import importlib
import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(relative_path: str) -> str:
    with open(os.path.join(REPO_ROOT, relative_path), encoding="utf-8") as handle:
        return handle.read()


class PreCommitHooksTest(unittest.TestCase):
    """.pre-commit-hooks.yaml — список хуков с нужным id и entry."""

    PATH = ".pre-commit-hooks.yaml"

    def setUp(self) -> None:
        self.abspath = os.path.join(REPO_ROOT, self.PATH)
        self.text = _read(self.PATH)

    def test_file_exists(self) -> None:
        self.assertTrue(os.path.isfile(self.abspath), f"нет файла {self.PATH}")

    def test_parses_as_yaml_list(self) -> None:
        # Хук-файлы pre-commit — это YAML-список верхнего уровня: каждая запись
        # начинается с "- ". Без pyyaml убеждаемся, что верхний уровень — список.
        stripped = [
            line
            for line in self.text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertTrue(stripped, "файл пустой")
        self.assertTrue(
            stripped[0].lstrip().startswith("- "),
            "верхний уровень .pre-commit-hooks.yaml должен быть списком (начинаться с '- ')",
        )

    def test_has_hook_id(self) -> None:
        self.assertIn("id: data-shield-ai", self.text)

    def test_entry_is_datashield_check(self) -> None:
        self.assertIn("entry: datashield check", self.text)

    def test_minimal_parse_id_and_entry(self) -> None:
        # Мини-разбор «ключ: значение» внутри единственной записи списка,
        # чтобы убедиться, что id и entry — реальные пары, а не подстроки в тексте.
        fields = {}
        for line in self.text.splitlines():
            body = line.lstrip("- ").strip()
            if not body or body.startswith("#") or ":" not in body:
                continue
            key, _, value = body.partition(":")
            fields.setdefault(key.strip(), value.strip())
        self.assertEqual(fields.get("id"), "data-shield-ai")
        self.assertEqual(fields.get("entry"), "datashield check")
        # Хук объявлен как python-язык — установка идёт через тот же пакет.
        self.assertEqual(fields.get("language"), "python")


class ActionYmlTest(unittest.TestCase):
    """action.yml — composite GitHub Action с inputs paths/min-severity."""

    PATH = "action.yml"

    def setUp(self) -> None:
        self.abspath = os.path.join(REPO_ROOT, self.PATH)
        self.text = _read(self.PATH)

    def test_file_exists(self) -> None:
        self.assertTrue(os.path.isfile(self.abspath), f"нет файла {self.PATH}")

    def test_has_name_and_description(self) -> None:
        self.assertIn("name:", self.text)
        self.assertIn("description:", self.text)

    def test_declares_inputs(self) -> None:
        self.assertIn("inputs:", self.text)
        # Оба объявленных входа должны присутствовать как ключи блока inputs.
        self.assertIn("paths:", self.text)
        self.assertIn("min-severity:", self.text)

    def test_runs_using_composite(self) -> None:
        self.assertIn("runs:", self.text)
        self.assertIn("using:", self.text)
        self.assertIn("composite", self.text)

    def test_steps_install_and_scan(self) -> None:
        # Composite-экшен ставит пакет и запускает CLI-проверку.
        self.assertIn("steps:", self.text)
        self.assertIn("pip install data-shield-ai", self.text)
        self.assertIn("datashield check", self.text)

    def test_minimal_parse_inputs_block(self) -> None:
        # Аккуратно вырезаем блок inputs: и убеждаемся, что paths и min-severity —
        # ключи именно этого блока (по отступу), а не случайные совпадения.
        lines = self.text.splitlines()
        inputs_indent = None
        input_keys = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if inputs_indent is None:
                if stripped.rstrip() == "inputs:":
                    inputs_indent = indent
                continue
            # Вышли из блока inputs (вернулись на тот же или меньший отступ).
            if indent <= inputs_indent:
                break
            # Ключи входов — на один уровень глубже "inputs:".
            if stripped.endswith(":") and indent == inputs_indent + 2:
                input_keys.append(stripped[:-1])
        self.assertIn("paths", input_keys)
        self.assertIn("min-severity", input_keys)


class PyprojectScriptsTest(unittest.TestCase):
    """pyproject.toml — console-scripts и пакеты для интеграций."""

    PATH = "pyproject.toml"

    def setUp(self) -> None:
        import tomllib  # stdlib на 3.11+

        with open(os.path.join(REPO_ROOT, self.PATH), "rb") as handle:
            self.data = tomllib.load(handle)

    def test_project_name(self) -> None:
        self.assertEqual(self.data["project"]["name"], "data-shield-ai")

    def test_scripts_present(self) -> None:
        scripts = self.data["project"]["scripts"]
        self.assertIn("datashield", scripts)
        self.assertIn("datashield-mcp", scripts)

    def test_datashield_entrypoint(self) -> None:
        scripts = self.data["project"]["scripts"]
        self.assertEqual(scripts["datashield"], "datashield.cli:main")

    def test_datashield_mcp_entrypoint(self) -> None:
        scripts = self.data["project"]["scripts"]
        self.assertEqual(
            scripts["datashield-mcp"],
            "datashield.integrations.mcp_server:serve_stdio",
        )

    def test_packages_include_integrations(self) -> None:
        packages = self.data["tool"]["setuptools"]["packages"]
        self.assertIn("datashield.integrations", packages)
        self.assertIn("datashield", packages)

    def test_runtime_has_no_dependencies(self) -> None:
        # Заявленная фишка проекта: zero-dependency рантайм.
        self.assertEqual(self.data["project"]["dependencies"], [])

    def test_entrypoints_are_importable(self) -> None:
        # console-script указывает на реальный объект module:attr — проверяем,
        # что и модуль, и атрибут существуют, а не только строка в TOML.
        scripts = self.data["project"]["scripts"]
        for target in (scripts["datashield"], scripts["datashield-mcp"]):
            module_name, _, attr = target.partition(":")
            module = importlib.import_module(module_name)
            self.assertTrue(
                hasattr(module, attr),
                f"{module_name} не содержит {attr}",
            )
            self.assertTrue(callable(getattr(module, attr)))


class IntegrationsImportTest(unittest.TestCase):
    """Пакет интеграций импортируется чисто и отдаёт публичный API."""

    def test_package_imports(self) -> None:
        importlib.import_module("datashield.integrations")

    def test_mcp_server_imports_and_exports_handle(self) -> None:
        module = importlib.import_module("datashield.integrations.mcp_server")
        self.assertTrue(callable(module.handle))
        self.assertTrue(callable(module.serve_stdio))

    def test_http_server_imports_and_exports_process(self) -> None:
        module = importlib.import_module("datashield.integrations.http_server")
        for name in ("process", "make_handler", "serve"):
            self.assertTrue(callable(getattr(module, name)), f"нет {name}")

    def test_logging_filter_imports_and_exports_filter(self) -> None:
        import logging

        module = importlib.import_module("datashield.integrations.logging_filter")
        self.assertTrue(issubclass(module.RedactingFilter, logging.Filter))


if __name__ == "__main__":
    unittest.main()
