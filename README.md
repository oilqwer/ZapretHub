# Zapret Hub

Графическая оболочка для Windows, которая устанавливает и обновляет [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) (Flowseal), подбирает рабочую стратегию обхода блокировок для YouTube и Discord, содержит встроенный Telegram-прокси и помощник по настройке AI DNS.

Автор: Ebowsky. Лицензия: **GPL-3.0-only** (см. [LICENSE](LICENSE)). Версия: **2.0.2** (C# / .NET 8, WebView2).

> Zapret Hub — независимый проект и не связан с Flowseal, bol-van, Telegram, Discord или Google. Программа управляет сетевыми настройками вашего компьютера; используйте её в соответствии с законодательством вашей страны. Программа предоставляется «как есть», без гарантий.

## Возможности

- Установка и обновление движка zapret напрямую из релизов Flowseal на GitHub; пользовательские списки, выбранная стратегия и настройки сохраняются при обновлении.
- Автоподбор стратегии (YouTube, Discord), ручной выбор, Game Filter, режимы IPSet, пользовательские списки доменов.
- Запуск как приложение или как служба Windows; значок в трее.
- Встроенный Telegram-прокси (MTProto поверх WebSocket, порт ядра [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) на C#).
- Помощник AI DNS (DoH-серверы для сервисов ИИ) с проверкой доступности.
- Диагностика системы (BFE, прокси, TCP timestamps, антивирусы, файлы движка). Обновление hosts временно недоступно: нужен подписанный список записей.

## Установка

1. Скачайте `ZapretHub.exe` со страницы [Releases](https://github.com/oilqwer/ZapretHub/releases) и проверьте SHA-256 по файлу `SHA256SUMS.txt`:
   ```powershell
   Get-FileHash .\ZapretHub.exe -Algorithm SHA256
   ```
2. Запустите от имени администратора (нужно для драйвера WinDivert). Нужны Windows 10/11 x64 и [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) (есть в Windows 11 и в актуальной Windows 10).
3. На первом запуске программа сама скачает zapret с GitHub Flowseal.

Файл не подписан сертификатом издателя, поэтому SmartScreen и антивирусы могут показать предупреждение; сверяйте SHA-256.

Данные приложения хранятся в `C:\ProgramData\ZapretHub` (движок, `settings.json`, журнал, резервная копия `engine.backup`).

## Как проверяются обновления

| Что | Источник | Проверка |
|---|---|---|
| Движок zapret | GitHub API `Flowseal/zapret-discord-youtube` (`releases/latest`) | HTTPS, репозиторий-владелец, **SHA-256 из поля `digest` ответа GitHub API**; без `digest` или при несовпадении установка отклоняется |
| Компоненты самого Zapret Hub (например, `hosts`) | подписанный манифест `manifest/components.json` в этом репозитории | подпись **Ed25519** (публичный ключ зашит в программу), SHA-256, защита от отката (`sequence`) |

Подписи разработчика Flowseal программа не проверяет: у его релизов её нет, проверяется только SHA-256 из GitHub API. Архив распаковывается во временную папку с защитой от выхода за её пределы; прежний движок сохраняется в `engine.backup`, при ошибке выполняется откат.

## Сборка

См. [BUILDING.md](BUILDING.md).

## Лицензии

Собственный код — GPL-3.0-only. Сторонние компоненты и их лицензии — в [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) и каталоге [licenses/](licenses/).
