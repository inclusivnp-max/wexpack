# WexPack (`wxp`)

[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-success?style=flat-square)](https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html)
[![Crypto](https://img.shields.io/badge/crypto-Argon2id%20%2B%20XChaCha20--Poly1305-blue?style=flat-square)](https://en.wikipedia.org/wiki/Authenticated_encryption)
[![FEC](https://img.shields.io/badge/recovery-Reed--Solomon%20GF(256)-blueviolet?style=flat-square)](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-lightgrey?style=flat-square)](Cargo.toml)

Современный кроссплатформенный архиватор на Rust: контентно-зависимая FastCDC-дедупликация, обратимые префильтры, компрессионный движок WexEngine (уровни 1–9), криптографическая аутентификация Argon2id / XChaCha20-Poly1305 и упреждающая коррекция ошибок Reed–Solomon GF(256).

---

## Архитектура и технологии

```
[ Input Stream / Safe Mmap ]
            │
            ▼
    [ FastCDC Chunking ]  ──► BLAKE3 хеширование
            │
            ▼
   [ Dedup Registry ]     ──► Пропуск повторяющихся блоков
            │
            ▼
   [ Smart Pre-Filters ]  ──► BCJ (x86/ARM64) / DictWord / Byte-Shuffle
            │
            ▼
   [ WexEngine 1..9 ]     ──► LZ77 MatchFinder ──► rANS / Context-Mixer
            │
            ▼
   [ Crypto Sealer ]      ──► Argon2id KDF ──► XChaCha20-Poly1305 AEAD
            │
            ▼
   [ Reed-Solomon FEC ]   ──► Генерация контрольных шардов GF(256)
            │
            ▼
      [ .wxp v2 File ]
```

| Компонент | Назначение | Реализация |
| :--- | :--- | :--- |
| **Дедупликация** | Быстрое разбиение потока на границы блоков | FastCDC (Gear-хеш, subminimum skipping) + глобальный потокобезопасный реестр BLAKE3 |
| **Префильтры** | Подготовка бинарных и текстовых данных | Реверсивные фильтры: BCJ для x86/ARM64, DictWord, байтовый Shuffle-4/8 |
| **Сжатие** | Баланс между скоростью и степенью упаковки | WexEngine: Hash-Chain LZ77, байтовый rANS и адаптивный Context-Mixer |
| **Криптография** | Защита от подделки и раскрытия данных | KDF Argon2id (защита от перебора) + XChaCha20-Poly1305 для чанков и метаданных |
| **Коррекция ошибок**| Автоматическое восстановление при повреждении | Reed–Solomon в поле GF(256) с полиномами Вандермонда |
| **Конвейер** | Управление памятью без OOM | Crossbeam каналы, Rayon пул воркеров, пул фиксированных буферов |

---

## Сборка и тестирование

Требуется компилятор Rust версии **1.95+**.

```sh
# Сборка релизной версии
cargo build --locked --release

# Запуск полного набора тестов
cargo test --locked

# Статический анализ
cargo clippy --locked --all-targets -- -D warnings
```

Исполняемый файл: `target/release/wxp` (`wxp.exe` для Windows).

---

## Примеры использования

### Стандартная упаковка и распаковка

```sh
# Упаковка файлов и папок с дедупликацией (уровень сжатия 5 по умолчанию)
wxp pack backup.wxp ./documents ./notes.txt -l 5 --dedup

# Детальный просмотр дерева архива и статистики сжатия
wxp list backup.wxp --detailed

# Верификация целостности всех чанков архива
wxp verify backup.wxp

# Распаковка всего содержимого в новую папку
wxp unpack backup.wxp -o ./restored

# Избирательное извлечение одного файла (без распаковки остальных)
wxp unpack backup.wxp -o ./output --file documents/report.pdf

# Замер скорости и сжатия на тестовых данных
wxp bench ./notes.txt
```

### Защита паролем и восстановление данных

```sh
# Создание зашифрованного архива с 10% избыточностью Reed-Solomon
wxp pack secure.wxp ./private -l 9 --dedup --solid --password --recovery 10%

# Просмотр содержимого зашифрованного архива
wxp list secure.wxp --password

# Проверка и транзакционное исправление повреждённых блоков
wxp verify secure.wxp --repair --password

# Извлечение из зашифрованного архива
wxp unpack secure.wxp -o ./private-restored --password
```

> **Безопасность ввода**: Флаг `--password` считывает пароль напрямую из терминала без эхо-вывода. В автоматизированных скриптах используйте `--password-env VAR_NAME`, чтобы секреты не сохранялись в аргументах процессов.

---

## Управление ресурсами

```sh
wxp pack big_archive.wxp ./dataset --threads 8 --memory-mib 1024
```

- Ограничение оперативной памяти задаётся флагом `--memory-mib`.
- Пул потоков управляется параметром `--threads`.
- Для файлов без подтверждения ядром их неизменяемости используется защищённое потоковое чтение (флаг `--no-mmap` отключает отображение памяти).
