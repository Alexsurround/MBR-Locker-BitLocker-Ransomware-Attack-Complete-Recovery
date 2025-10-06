# Восстановление целостности системы после ransomware

## 🔧 Обзор

После удаления MBR Locker ransomware необходимо проверить и восстановить целостность системных файлов Windows. Malware мог повредить критически важные компоненты операционной системы.

**Две ключевые утилиты:**
1. **SFC** (System File Checker) - проверяет и восстанавливает системные файлы
2. **DISM** (Deployment Image Servicing and Management) - восстанавливает хранилище компонентов Windows

---

## 📋 Когда использовать

### Признаки повреждения системных файлов:

- ✅ Windows Update не работает
- ✅ Программы вылетают с системными ошибками
- ✅ Отсутствуют DLL файлы
- ✅ "Синий экран смерти" (BSOD)
- ✅ Службы Windows не запускаются
- ✅ Не открываются системные приложения (Settings, Store)
- ✅ Ошибки реестра
- ✅ После удаления malware система работает нестабильно

---

## 🎯 Правильная последовательность

**⚠️ ВАЖНО:** Порядок имеет значение!

```
1. DISM (восстановить хранилище компонентов)
   ↓
2. SFC (восстановить системные файлы из исправленного хранилища)
   ↓
3. Повторить SFC (для финальной проверки)
```

**Почему именно так?**
- SFC использует хранилище компонентов для восстановления
- Если хранилище повреждено → SFC не может восстановить файлы
- DISM сначала исправляет хранилище → потом SFC работает корректно

---

## ✅ Метод 1: Полная последовательность (Рекомендуется)

### Шаг 1: Проверка хранилища компонентов (DISM CheckHealth)

**Быстрая проверка состояния:**

```cmd
REM Откройте CMD от имени администратора
REM Win + X → "Командная строка (администратор)"

DISM /Online /Cleanup-Image /CheckHealth
```

**Время выполнения:** 10-30 секунд

**Возможные результаты:**
```
✅ "No component store corruption detected" 
   → Хранилище в порядке, можно сразу к SFC

⚠️ "The component store is repairable"
   → Нужно восстановление через RestoreHealth

❌ "The component store corruption was detected"
   → Требуется полное восстановление
```

### Шаг 2: Сканирование хранилища (DISM ScanHealth)

**Более глубокая проверка:**

```cmd
DISM /Online /Cleanup-Image /ScanHealth
```

**Время выполнения:** 5-10 минут

**Что делает:**
- Сканирует хранилище компонентов на повреждения
- Не исправляет, только проверяет
- Создает отчет в журнале событий

**Проверка результатов:**
```cmd
REM Просмотр лога DISM
notepad C:\Windows\Logs\DISM\dism.log
```

### Шаг 3: Восстановление хранилища (DISM RestoreHealth)

**Полное восстановление:**

```cmd
DISM /Online /Cleanup-Image /RestoreHealth
```

**⏱️ Время выполнения:** 20-40 минут (зависит от скорости интернета и повреждений)

**Что происходит:**
```
[0%]    Инициализация...
[10%]   Сканирование хранилища компонентов...
[30%]   Загрузка исправных файлов с Windows Update...
[60%]   Замена поврежденных компонентов...
[90%]   Проверка целостности...
[100%]  Операция успешно завершена.
```

**⚠️ Требуется интернет!** DISM скачивает исправные файлы с серверов Microsoft.

**Если нет интернета, используйте установочный ISO:**

```cmd
REM Смонтируйте ISO Windows 10/11
REM Допустим, он смонтирован как диск E:

DISM /Online /Cleanup-Image /RestoreHealth /Source:E:\sources\install.wim /LimitAccess
```

### Шаг 4: Проверка системных файлов (SFC)

**После восстановления хранилища запустите SFC:**

```cmd
sfc /scannow
```

**⏱️ Время выполнения:** 10-30 минут

**Процесс:**
```
Начало проверки системы. Этот процесс может занять некоторое время.

Начало этапа проверки при проверке системы.
Проверка 100 % завершена.

Программа защиты ресурсов Windows обнаружила поврежденные файлы
и успешно их восстановила.
Подробные сведения см. в файле CBS.Log:
C:\Windows\Logs\CBS\CBS.log
```

**Возможные результаты:**

✅ **"Не обнаружила нарушений целостности"**
```
Программа защиты ресурсов Windows не обнаружила нарушений целостности.
```
→ Система в порядке!

✅ **"Обнаружила и восстановила"**
```
Программа защиты ресурсов Windows обнаружила поврежденные файлы
и успешно их восстановила.
```
→ Проблемы исправлены!

⚠️ **"Обнаружила, но не смогла восстановить"**
```
Программа защиты ресурсов Windows обнаружила поврежденные файлы,
но не может восстановить некоторые из них.
```
→ Нужны дополнительные действия (см. ниже)

❌ **"Не удалось выполнить"**
```
Программа защиты ресурсов Windows не может выполнить запрошенную операцию.
```
→ Запустите в безопасном режиме

### Шаг 5: Повторная проверка SFC

**После первого SFC запустите еще раз:**

```cmd
sfc /scannow
```

**Почему?**
- Первый проход может восстановить не все
- Некоторые файлы зависят от других
- Второй проход "добивает" оставшиеся проблемы

**Если второй SFC показывает "нет нарушений" → ✅ Готово!**

### Шаг 6: Проверка логов

**Просмотр подробностей восстановления:**

```cmd
REM Откройте лог CBS (Component-Based Servicing)
notepad C:\Windows\Logs\CBS\CBS.log
```

**Ищите строки:**
```
[SR] Cannot repair member file
[SR] Repairing corrupted file
[SR] Successfully repaired file
```

**Экспорт только ошибок SFC в отдельный файл:**

```cmd
findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log > "%userprofile%\Desktop\sfcdetails.txt"
```

**Просмотр DISM лога:**

```cmd
notepad C:\Windows\Logs\DISM\dism.log
```

---

## ✅ Метод 2: Полный Batch-скрипт (автоматизация)

### Сохраните как `System_Repair.bat`:

```batch
@echo off
echo ========================================
echo Полное восстановление целостности Windows
echo ========================================
echo.
echo Этот процесс займет 40-60 минут.
echo Не закрывайте окно и не выключайте компьютер!
echo.
pause

REM Проверка прав администратора
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ОШИБКА: Запустите от имени администратора!
    pause
    exit
)

echo.
echo ========================================
echo [1/6] Проверка хранилища компонентов...
echo ========================================
DISM /Online /Cleanup-Image /CheckHealth
if %errorLevel% neq 0 (
    echo Обнаружены проблемы. Продолжаем восстановление...
)
echo.
pause

echo.
echo ========================================
echo [2/6] Глубокое сканирование хранилища...
echo ========================================
DISM /Online /Cleanup-Image /ScanHealth
echo.
pause

echo.
echo ========================================
echo [3/6] Восстановление хранилища (может занять 30+ минут)...
echo ========================================
DISM /Online /Cleanup-Image /RestoreHealth
if %errorLevel% neq 0 (
    echo ВНИМАНИЕ: Ошибка при восстановлении!
    echo Проверьте подключение к интернету.
    pause
)
echo.
pause

echo.
echo ========================================
echo [4/6] Первая проверка системных файлов...
echo ========================================
sfc /scannow
echo.
pause

echo.
echo ========================================
echo [5/6] Повторная проверка системных файлов...
echo ========================================
sfc /scannow
echo.
pause

echo.
echo ========================================
echo [6/6] Экспорт деталей на рабочий стол...
echo ========================================
findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log > "%userprofile%\Desktop\SFC_Details.txt"
echo Готово! Файл сохранен: %userprofile%\Desktop\SFC_Details.txt
echo.

echo ========================================
echo Восстановление завершено!
echo ========================================
echo.
echo Рекомендуется перезагрузить компьютер.
echo.
set /p reboot="Перезагрузить сейчас? (Y/N): "
if /i "%reboot%"=="Y" shutdown /r /t 10
if /i "%reboot%"=="y" shutdown /r /t 10

pause
```

**Запуск:**
1. Сохраните как `System_Repair.bat`
2. Правой кнопкой → **"Запуск от имени администратора"**
3. Следуйте инструкциям на экране

---

## ✅ Метод 3: PowerShell скрипт (с прогресс-баром)

### Сохраните как `Repair-SystemIntegrity.ps1`:

```powershell
#Requires -RunAsAdministrator

function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Восстановление целостности системы" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. DISM CheckHealth
Show-Progress -Activity "Проверка системы" -Status "Проверка хранилища компонентов..." -PercentComplete 0
Write-Host "[1/5] DISM CheckHealth..." -ForegroundColor Yellow
$checkResult = & DISM /Online /Cleanup-Image /CheckHealth
Write-Host "Результат: $LASTEXITCODE" -ForegroundColor $(if($LASTEXITCODE -eq 0){"Green"}else{"Red"})
Start-Sleep -Seconds 2

# 2. DISM ScanHealth
Show-Progress -Activity "Проверка системы" -Status "Глубокое сканирование..." -PercentComplete 20
Write-Host "[2/5] DISM ScanHealth..." -ForegroundColor Yellow
& DISM /Online /Cleanup-Image /ScanHealth
Start-Sleep -Seconds 2

# 3. DISM RestoreHealth
Show-Progress -Activity "Восстановление" -Status "Восстановление хранилища компонентов (это займет время)..." -PercentComplete 40
Write-Host "[3/5] DISM RestoreHealth..." -ForegroundColor Yellow
Write-Host "⏱️ Это может занять 20-40 минут. Пожалуйста, подождите..." -ForegroundColor Cyan
& DISM /Online /Cleanup-Image /RestoreHealth
Start-Sleep -Seconds 2

# 4. SFC первый проход
Show-Progress -Activity "Проверка файлов" -Status "Первая проверка системных файлов..." -PercentComplete 60
Write-Host "[4/5] SFC /scannow (первый проход)..." -ForegroundColor Yellow
& sfc /scannow
Start-Sleep -Seconds 2

# 5. SFC второй проход
Show-Progress -Activity "Проверка файлов" -Status "Повторная проверка..." -PercentComplete 80
Write-Host "[5/5] SFC /scannow (повторная проверка)..." -ForegroundColor Yellow
& sfc /scannow

# Экспорт результатов
Show-Progress -Activity "Завершение" -Status "Экспорт результатов..." -PercentComplete 95
$logPath = "$env:USERPROFILE\Desktop\SFC_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Get-Content "$env:windir\Logs\CBS\CBS.log" | Select-String "\[SR\]" | Out-File -FilePath $logPath

Write-Progress -Activity "Проверка системы" -Completed
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "✅ Восстановление завершено!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Отчет сохранен: $logPath" -ForegroundColor Cyan
Write-Host ""

# Предложение перезагрузки
$reboot = Read-Host "Перезагрузить компьютер? (Y/N)"
if ($reboot -eq "Y" -or $reboot -eq "y") {
    Write-Host "Перезагрузка через 10 секунд..." -ForegroundColor Yellow
    shutdown /r /t 10
}
```

**Запуск:**
```powershell
# В PowerShell от имени администратора
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\Repair-SystemIntegrity.ps1
```

---

## 🚨 Устранение проблем

### Проблема 1: "DISM не может подключиться к Windows Update"

**Ошибка:**
```
Error: 0x800f0906
The source files could not be downloaded.
```

**Решение A: Проверьте интернет**
```cmd
ping microsoft.com
```

**Решение B: Используйте ISO образ Windows:**
```cmd
REM 1. Скачайте ISO Windows 10/11
REM 2. Смонтируйте (двойной клик или через 7-Zip)
REM 3. Запустите DISM с параметром Source

DISM /Online /Cleanup-Image /RestoreHealth /Source:E:\sources\install.wim /LimitAccess
```
Где E: - буква смонтированного ISO

**Решение C: Сбросьте компоненты Windows Update:**
```cmd
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver

ren C:\Windows\SoftwareDistribution SoftwareDistribution.old
ren C:\Windows\System32\catroot2 catroot2.old

net start wuauserv
net start cryptSvc
net start bits
net start msiserver

DISM /Online /Cleanup-Image /RestoreHealth
```

### Проблема 2: "SFC не может восстановить некоторые файлы"

**Ошибка в логе:**
```
[SR] Cannot repair member file [filename]
```

**Решение A: Запустите в безопасном режиме:**
```
1. Shift + Перезагрузка
2. Troubleshoot → Advanced Options → Startup Settings → Restart
3. F4 - Safe Mode
4. Запустите SFC снова
```

**Решение B: Восстановите вручную из install.wim:**
```cmd
REM Найдите поврежденный файл в логе
REM Например: C:\Windows\System32\kernel32.dll

REM Смонтируйте install.wim
DISM /Mount-Wim /WimFile:E:\sources\install.wim /index:1 /MountDir:C:\mount

REM Скопируйте файл
copy C:\mount\Windows\System32\kernel32.dll C:\Windows\System32\kernel32.dll /Y

REM Размонтируйте
DISM /Unmount-Wim /MountDir:C:\mount /discard
```

### Проблема 3: SFC зависает на определенном проценте

**Симптом:** SFC останавливается на 20%, 40% или 70%

**Решение:**
```cmd
REM 1. Подождите минимум 30 минут (может быть медленно)

REM 2. Если действительно завис, перезагрузитесь и запустите:
sfc /scannow /offboot
