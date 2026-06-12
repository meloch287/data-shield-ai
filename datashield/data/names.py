"""Компактные газеттиры имён (RU + EN) для быстрой детекции без ML.

Хранятся как frozenset в нижнем регистре — импорт модуля сразу даёт готовые
множества, поиск O(1), холодного старта нет (в отличие от загрузки ML-модели).
Списки курированы по частотности; полноту добирают эвристики (отчества,
контекст) и опциональные ML-плагины.
"""
from __future__ import annotations

# Русские мужские имена (полные формы).
_RU_MALE = """
Александр Алексей Анатолий Андрей Антон Аркадий Артём Артем Артур Богдан Борис
Вадим Валентин Валерий Василий Виктор Виталий Владимир Владислав Вячеслав
Геннадий Георгий Глеб Григорий Давид Даниил Денис Дмитрий Евгений Егор Захар
Иван Игорь Илья Кирилл Константин Лев Леонид Макар Максим Марк Матвей Михаил
Назар Никита Николай Олег Павел Пётр Петр Платон Роман Руслан Савелий Святослав
Семён Семен Сергей Станислав Степан Тимофей Тимур Фёдор Федор Филипп Эдуард
Эмиль Юрий Ян Ярослав
""".split()

# Русские женские имена (полные формы).
_RU_FEMALE = """
Александра Алёна Алена Алина Алиса Алла Анастасия Ангелина Анна Антонина
Валентина Валерия Варвара Василиса Вера Вероника Виктория Галина Дарья Диана
Ева Евгения Екатерина Елена Елизавета Жанна Зинаида Зоя Инна Ирина Камилла
Карина Кира Кристина Ксения Лариса Лидия Любовь Людмила Маргарита Марина Мария
Милана Надежда Наталья Наталия Нина Оксана Олеся Ольга Полина Раиса Регина
Римма Светлана Серафима София Софья Таисия Тамара Татьяна Ульяна Эвелина Юлия
Яна Ярослава
""".split()

# Частые уменьшительные/разговорные формы.
_RU_DIMINUTIVES = """
Саша Сашка Серёжа Сережа Серёга Серега Дима Димон Вова Вовка Володя Вася Васька
Петя Петька Коля Колян Миша Мишка Лёша Леша Лёня Леня Женя Гоша Толя Слава Витя
Юра Боря Гена Гриша Костя Стас Тёма Тема Даня Кирюша Максик
Настя Настенька Катя Катюша Маша Машенька Даша Дашка Лена Леночка Таня Танюша
Оля Оленька Света Светка Ира Ирочка Юля Юленька Лиза Лизонька Соня Сонечка
Аня Анечка Вика Викуся Ксюша Поля Алёнка Аленка Надя Люда Тома
""".split()

# Английские имена (по частотности).
_EN_NAMES = """
James John Robert Michael William David Richard Joseph Thomas Charles
Christopher Daniel Matthew Anthony Mark Donald Steven Andrew Paul Joshua Kenneth
Kevin Brian George Timothy Ronald Edward Jason Jeffrey Ryan Jacob Gary Nicholas
Eric Jonathan Stephen Larry Justin Scott Brandon Benjamin Samuel Gregory
Alexander Patrick Frank Raymond Jack Dennis Jerry Tyler Aaron Jose Adam Nathan
Henry Zachary Douglas Peter Kyle Ethan Jeremy Walter Christian Keith Roger Noah
Gerald Carl Terry Sean Austin Arthur Lawrence Jesse Dylan Bryan Joe Jordan Billy
Bruce Albert Willie Gabriel Logan Alan Juan Wayne Roy Ralph Randy Eugene Vincent
Russell Louis Bobby Philip Johnny Mason Liam Oliver Elijah
Mary Patricia Jennifer Linda Elizabeth Barbara Susan Jessica Sarah Karen Nancy
Lisa Margaret Betty Sandra Ashley Dorothy Kimberly Emily Donna Michelle Carol
Amanda Melissa Deborah Stephanie Rebecca Sharon Laura Cynthia Kathleen Amy
Angela Shirley Anna Brenda Pamela Emma Nicole Helen Samantha Katherine Christine
Debra Rachel Catherine Carolyn Janet Ruth Maria Heather Diane Virginia Julie
Joyce Victoria Olivia Kelly Christina Joan Evelyn Lauren Judith Megan Andrea
Hannah Jacqueline Martha Gloria Teresa Ann Sara Madison Grace Sophia Isabella
Mia Charlotte Amelia Harper Abigail
""".split()


def _norm(words) -> frozenset:
    return frozenset(w.lower() for w in words)


RU_GIVEN_NAMES = _norm(_RU_MALE) | _norm(_RU_FEMALE) | _norm(_RU_DIMINUTIVES)
EN_GIVEN_NAMES = _norm(_EN_NAMES)
ALL_GIVEN_NAMES = RU_GIVEN_NAMES | EN_GIVEN_NAMES


def is_given_name(token: str) -> bool:
    """Известно ли это слово как личное имя (регистр игнорируется)."""
    return token.lower() in ALL_GIVEN_NAMES
