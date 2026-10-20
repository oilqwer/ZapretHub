# Сборка Zapret Hub

Нужны Windows 10/11 x64 и [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (проверено на 8.0.426). Python и PyInstaller не требуются.

```powershell
git clone https://github.com/oilqwer/ZapretHub.git
cd ZapretHub\src\ZapretHub
dotnet publish -c Release -o ..\..\dist
```

Результат — один самодостаточный файл `dist\ZapretHub.exe` (self-contained, single-file, win-x64, версия 2.0.2). Параметры сборки заданы в `src\ZapretHub\ZapretHub.csproj`; пакеты NuGet: `Microsoft.Web.WebView2 1.0.2792.45`, `BouncyCastle.Cryptography 2.4.0`.

### Воспроизводимая сборка

Релизный EXE собран из тега `v2.0.2` командой

```powershell
dotnet publish -c Release -p:IncludeSourceRevisionInInformationalVersion=false -o ..\..\dist
```

(флаг убирает из версии EXE хэш коммита, иначе он меняет файл). Его SHA-256 указан в `SHA256SUMS.txt` релиза. При .NET SDK 8.0.426 и пакетах NuGet из `ZapretHub.csproj` пересборка из свежего клона даёт побитово тот же файл; с другой версией SDK результат может отличаться.

## Тестовая сборка

Тестовые режимы (`--integritytest`, `--tgmocktest` и др.) работают только с переменной окружения `ZAPRETHUB_DATA` (изолированная папка данных) и не трогают систему. Сборка с хуками для локального манифеста:

```powershell
dotnet publish -c Release -p:ManifestTest=true -p:AssemblyName=ZapretHub-ManifestTest -p:IntermediateOutputPath=obj\test\ -o ..\..\dist-test
```

В рабочем EXE этих хуков нет (`#if MANIFEST_TEST`).

Проверка Ed25519/SHA-256 и разбора релизов (нужен Python с пакетом `cryptography`):

```powershell
python tests\make_fixtures.py $env:TEMP\zh-fixtures
$env:ZAPRETHUB_DATA = "$env:TEMP\zh-data"; $env:__COMPAT_LAYER = "RunAsInvoker"
.\dist-test\ZapretHub-ManifestTest.exe --integritytest $env:TEMP\zh-fixtures
# отчёт: $env:TEMP\zh-fixtures\report.txt
```

## Подписанный манифест

Файлы `manifest/components.json` и `components.json.sig` подписывает владелец проекта своим приватным ключом Ed25519 (хранится вне репозитория). Подпись — base64 от сырых байтов `components.json`; не меняйте окончания строк в этих файлах (`.gitattributes` отключает преобразование).
