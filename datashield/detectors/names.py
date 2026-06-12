"""Быстрый детектор имён (PERSON) без ML: газеттир + эвристики.

Сигналы по убыванию точности:
  1. Русское отчество (суффиксы -ович/-евна/...) — почти однозначно ФИО.
  2. Контекст ("меня зовут X", "Mr. X", "Dear X").
  3. Известное имя из газеттира + заглавная фамилия рядом.
  4. Одиночное известное имя — низкая уверенность (ниже порога по умолчанию),
     чтобы не маскировать слова-омонимы (Вера, Любовь, Roman...).

Всё на регулярках и поиске по множеству — холодного старта нет. Для максимальной
полноты есть опциональные ML-плагины (Presidio/GLiNER), см. detectors/ml_plugin
и detectors/gliner_plugin.
"""
from __future__ import annotations

import re
from typing import List

from datashield.data.names import EN_GIVEN_NAMES, RU_GIVEN_NAMES
from datashield.detectors.base import Finding

__all__ = ["NameDetector", "build", "build_optional"]

# Полный список — для структурных проходов (тройка/пара), где соседние слова
# снимают неоднозначность. Голое «-ич» сюда входит (Ильич, в составе ФИО).
_PATRONYMIC = r"(?:ович|евич|ьевич|иевич|ич|овна|евна|ьевна|иевна|инична|инишна)"
# Сильные суффиксы — для одиночного слова без контекста: без голого «-ич»,
# чтобы не ловить нарицательные «Кирпич/Кулич/Москвич/Паралич».
_PATRONYMIC_STRONG = r"(?:ович|евич|ьевич|иевич|овна|евна|ьевна|иевна|инична|инишна)"
_RU_WORD = r"[А-ЯЁ][а-яё]+"
_EN_WORD = r"[A-Z][a-z]+"

# Частые английские слова в роли «фамилии» — отсекают ложные пары
# («Mark Down», «Grace Period», «Will Power»).
_EN_COMMON_FOLLOWERS = frozenset(
    """down up now then here there period power day time street road avenue please
    well off out again too also not no yes all more less today tomorrow soon later
    only just even still back forward away home left right""".split()
)


class NameDetector:
    """Детектор имён. По умолчанию — только высокоточные сигналы.

    bare_only=True включает агрессивный режим: маскировать одиночные известные
    имена (риск омонимов вроде «Вера»/«Roman»), поэтому по умолчанию выключен.
    """

    type = "PERSON"

    def __init__(self, bare_only: bool = False) -> None:
        self.bare_only = bare_only
        self.name = "names_aggressive" if bare_only else "names"
        # Тройка ФИО, где одно из слов — отчество (два частых порядка).
        self._ru_triplet = re.compile(
            rf"(?<!\w)(?:{_RU_WORD}\s+{_RU_WORD}{_PATRONYMIC}\s+{_RU_WORD}"
            rf"|{_RU_WORD}\s+{_RU_WORD}\s+{_RU_WORD}{_PATRONYMIC})(?!\w)"
        )
        # Имя + Отчество.
        self._ru_name_patronymic = re.compile(
            rf"(?<!\w){_RU_WORD}\s+{_RU_WORD}{_PATRONYMIC}(?!\w)"
        )
        # Одиночное отчество — только сильные суффиксы (без голого «-ич»).
        self._ru_patronymic = re.compile(
            rf"(?<!\w){_RU_WORD}{_PATRONYMIC_STRONG}(?!\w)"
        )
        # Контекст RU: триггер регистронезависим, само имя — с заглавной.
        self._ru_context = re.compile(
            r"(?i:меня зовут|зовут|моё имя|мое имя|господин|госпожа|г-н|г-жа"
            r"|гражданин|гражданка|уважаемый|уважаемая|фамилия|по фамилии"
            r"|подпись|клиент|пациент|сотрудник)"
            rf"\s+({_RU_WORD}(?:\s+{_RU_WORD}){{0,2}})"
        )
        # Заглавная пара (проверим, что первое слово — известное имя).
        self._ru_pair = re.compile(rf"(?<!\w)({_RU_WORD})\s+({_RU_WORD})(?!\w)")
        self._ru_single = re.compile(rf"(?<!\w){_RU_WORD}(?!\w)")

        # Английские титулы.
        self._en_title = re.compile(
            r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Madam)\.?\s+"
            rf"({_EN_WORD}(?:\s+{_EN_WORD})?)"
        )
        self._en_context = re.compile(
            r"(?i:my name is|i am|i'm|sincerely,?|best regards,?|regards,?|dear)"
            rf"\s+({_EN_WORD}(?:\s+{_EN_WORD}){{0,2}})"
        )
        self._en_pair = re.compile(rf"\b({_EN_WORD})\s+({_EN_WORD})\b")
        self._en_single = re.compile(rf"\b{_EN_WORD}\b")

    def detect(self, text: str) -> List[Finding]:
        out: List[Finding] = []

        def add(start, end, conf):
            out.append(Finding("PERSON", start, end, text[start:end], conf, self.name))

        if self.bare_only:
            # Агрессивный режим: одиночные известные имена (низкая уверенность).
            for m in self._ru_single.finditer(text):
                if m.group().lower() in RU_GIVEN_NAMES:
                    add(m.start(), m.end(), 0.7)
            for m in self._en_single.finditer(text):
                if m.group().lower() in EN_GIVEN_NAMES:
                    add(m.start(), m.end(), 0.7)
            return out

        # Высокоточные сигналы (включены по умолчанию).
        for m in self._ru_triplet.finditer(text):
            add(m.start(), m.end(), 0.92)
        for m in self._ru_name_patronymic.finditer(text):
            add(m.start(), m.end(), 0.9)
        for m in self._ru_patronymic.finditer(text):
            add(m.start(), m.end(), 0.82)
        for m in self._ru_context.finditer(text):
            add(m.start(1), m.end(1), 0.85)
        for m in self._ru_pair.finditer(text):
            if m.group(1).lower() in RU_GIVEN_NAMES:
                add(m.start(), m.end(), 0.8)

        for m in self._en_title.finditer(text):
            add(m.start(1), m.end(1), 0.85)
        for m in self._en_context.finditer(text):
            add(m.start(1), m.end(1), 0.85)
        for m in self._en_pair.finditer(text):
            if (
                m.group(1).lower() in EN_GIVEN_NAMES
                and m.group(2).lower() not in _EN_COMMON_FOLLOWERS
            ):
                add(m.start(), m.end(), 0.8)

        return out


def build() -> List[NameDetector]:
    return [NameDetector(bare_only=False)]


def build_optional() -> List[NameDetector]:
    return [NameDetector(bare_only=True)]
