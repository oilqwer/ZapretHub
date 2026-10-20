# Сторонние компоненты Zapret Hub 2.0

Собственный код Zapret Hub — **GPL-3.0-only** (© Ebowsky), см. [LICENSE](LICENSE). Этот файл не является юридической консультацией: он перечисляет компоненты, их авторов и лицензии. Полные тексты лежат в [licenses/](licenses/) — это файлы из пакетов NuGet и .NET без изменений.

## 1. Входит в ZapretHub.exe

| Компонент | Версия | Лицензия | Текст |
|---|---|---|---|
| .NET Runtime (CoreCLR, библиотеки) — self-contained | 8.0.32 | MIT, © .NET Foundation and Contributors | [dotnet-runtime-MIT.txt](licenses/dotnet-runtime-MIT.txt), [dotnet-runtime-THIRD-PARTY-NOTICES.txt](licenses/dotnet-runtime-THIRD-PARTY-NOTICES.txt) |
| .NET Windows Desktop Runtime (WinForms) | 8.0.32 | MIT, © .NET Foundation and Contributors | [dotnet-windowsdesktop-MIT.txt](licenses/dotnet-windowsdesktop-MIT.txt) |
| Microsoft.Web.WebView2 (SDK-обёртки) | 1.0.2792.45 | BSD-3-Clause, © Microsoft Corporation | [WebView2-BSD-3-Clause.txt](licenses/WebView2-BSD-3-Clause.txt), [WebView2-NOTICE.txt](licenses/WebView2-NOTICE.txt) |
| BouncyCastle.Cryptography (Ed25519) | 2.4.0 | MIT, © The Legion of the Bouncy Castle Inc. | [BouncyCastle.Cryptography-MIT.md](licenses/BouncyCastle.Cryptography-MIT.md) |

Лицензии MIT и BSD-3-Clause совместимы с GPL-3.0.

## 2. Производная работа

| Компонент | Лицензия | Примечание |
|---|---|---|
| [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (Flowseal) | MIT, © 2026 Flowseal | Telegram-прокси (`TgProxy.cs`, `TgProxyCore.cs`) — порт ядра на C#. Текст: [tg-ws-proxy-MIT.txt](licenses/tg-ws-proxy-MIT.txt) |

## 3. Скачивается программой при работе (в репозиторий и в EXE не входит)

| Компонент | Автор | Лицензия | Источник |
|---|---|---|---|
| zapret-discord-youtube (`general*.bat`, `service.bat`, списки, `winws.exe`) | Flowseal, на основе работы bol-van | MIT | https://github.com/Flowseal/zapret-discord-youtube |
| zapret / winws | bol-van | MIT | https://github.com/bol-van/zapret |
| WinDivert (`WinDivert.dll`, `WinDivert64.sys`) | basil00 | LGPL-3.0 или GPL-2.0 на выбор | https://github.com/basil00/WinDivert |
| Cygwin runtime (`cygwin1.dll`, в архиве Flowseal) | Red Hat / сообщество Cygwin | LGPL-3.0 с исключениями | https://cygwin.com |

Zapret Hub **не распространяет** эти файлы: приложение на компьютере пользователя само скачивает официальный архив у Flowseal и проверяет его SHA-256. Тексты их лицензий содержатся в самом архиве и в репозиториях авторов. Если вы будете раздавать архив zapret, WinDivert или `cygwin1.dll` самостоятельно, вы становитесь их распространителем и должны выполнить условия соответствующих лицензий.

## 4. Окружение и сервисы

- Microsoft Edge WebView2 Runtime — компонент Windows/Edge, устанавливается отдельно (лицензия Microsoft), в EXE не входит.
- Серверы DoH для AI DNS, GitHub API и jsDelivr — сторонние сервисы; их использование регулируется их условиями. Zapret Hub не аффилирован с ними.
