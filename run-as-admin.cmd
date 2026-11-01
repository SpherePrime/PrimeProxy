@echo off
rem Запуск PrimeBypass от имени администратора.
rem
rem Движку обхода (winws2) в манифесте требуется повышение прав: без него
rem Windows откажет в запуске (ошибка 740), потому что движку нужен доступ
rem к драйверу WinDivert.
rem
rem Запускать так: правой кнопкой по этому файлу -> «Запуск от имени
rem администратора». Окно UAC нужно подтвердить.
rem
rem Файл не обязателен: оболочка сама просит права при старте (см.
rem next\app-shell\electron\main.cjs) и перезапускается повышенной. Этот
rem ярлык просто избавляет от лишнего шага, когда права нужны сразу.
rem
rem Ядро (primecore-server) оболочка поднимает сама из target\release.

cd /d "%~dp0next\app-shell"
start "" "node_modules\electron\dist\electron.exe" .
