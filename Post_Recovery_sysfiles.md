# Восстановление прав доступа к системным папкам после ransomware-атаки

## 🚨 Проблема

После удаления MBR Locker ransomware обнаружены проблемы с установкой программ:
- Инсталляторы не запускаются или выдают ошибки
- "Отказано в доступе" при установке в Program Files
- "Недостаточно прав" даже от имени администратора
- Некоторые программы не могут записывать в свои папки

**Причина:** Malware изменил права доступа (ACL - Access Control Lists) к критическим системным папкам.

---

## 🔍 Диагностика проблемы

### Проверьте права доступа к ключевым папкам:

```cmd
# Откройте CMD от имени администратора
# Проверьте текущие права

icacls "C:\Program Files"
icacls "C:\Program Files (x86)"
icacls "C:\Windows"
icacls "C:\ProgramData"
```

**Нормальный вывод должен включать:**
```
BUILTIN\Administrators:(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
CREATOR OWNER:(OI)(CI)(IO)(F)
```

**Проблемный вывод:**
```
Everyone:(N)  - НЕТ ДОСТУПА
Или полное отсутствие стандартных групп
```

### Типичные ошибки при установке программ:

```
Error 5: Access is denied
Error 1920: Service failed to start
Error 1402: Could not open key
Error 2502/2503: Internal Error (MSI installer)
The system administrator has set policies...
```

---

## ✅ Решение 1: Автоматическое восстановление прав (Рекомендуется)

### Метод A: Через встроенную утилиту icacls

**Восстановление Program Files:**

```cmd
REM Запустите CMD от имени администратора

REM 1. Восстановить владельца
takeown /F "C:\Program Files" /R /D Y
takeown /F "C:\Program Files (x86)" /R /D Y

REM 2. Сбросить права к значениям по умолчанию
icacls "C:\Program Files" /reset /T /C /Q
icacls "C:\Program Files (x86)" /reset /T /C /Q

REM 3. Установить стандартные права
icacls "C:\Program Files" /grant "SYSTEM:(OI)(CI)F" /T /C /Q
icacls "C:\Program Files" /grant "Administrators:(OI)(CI)F" /T /C /Q
icacls "C:\Program Files" /grant "Users:(OI)(CI)RX" /T /C /Q

icacls "C:\Program Files (x86)" /grant "SYSTEM:(OI)(CI)F" /T /C /Q
icacls "C:\Program Files (x86)" /grant "Administrators:(OI)(CI)F" /T /C /Q
icacls "C:\Program Files (x86)" /grant "Users:(OI)(CI)RX" /T /C /Q
```

**⚠️ Предупреждение:** Процесс может занять 10-30 минут для большой папки Program Files.

**Восстановление ProgramData:**

```cmd
takeown /F "C:\ProgramData" /R /D Y
icacls "C:\ProgramData" /reset /T /C /Q
icacls "C:\ProgramData" /grant "SYSTEM:(OI)(CI)F" /T /C /Q
icacls "C:\ProgramData" /grant "Administrators:(OI)(CI)F" /T /C /Q
icacls "C:\ProgramData" /grant "Users:(OI)(CI)M" /T /C /Q
```

**Восстановление Windows (ОСТОРОЖНО!):**

```cmd
REM Только если есть проблемы с Windows
takeown /F "C:\Windows" /R /D Y
icacls "C:\Windows" /reset /T /C /Q
```

**⚠️ ВНИМАНИЕ:** Восстановление прав на C:\Windows может занять 1-2 часа!

---

## ✅ Решение 2: PowerShell скрипт (Быстрее и безопаснее)

### Скрипт для восстановления прав доступа:

```powershell
# Запустите PowerShell от имени администратора

# Функция для восстановления прав
function Restore-FolderPermissions {
    param(
        [string]$Path,
        [string]$FolderName
    )
    
    Write-Host "Восстановление прав для: $FolderName" -ForegroundColor Yellow
    
    try {
        # Восстановить владельца
        Write-Host "  - Восстановление владельца..." -ForegroundColor Cyan
        & takeown /F $Path /R /D Y | Out-Null
        
        # Сбросить права
        Write-Host "  - Сброс прав доступа..." -ForegroundColor Cyan
        & icacls $Path /reset /T /C /Q | Out-Null
        
        # Установить стандартные права
        Write-Host "  - Установка стандартных прав..." -ForegroundColor Cyan
        & icacls $Path /grant "SYSTEM:(OI)(CI)F" /T /C /Q | Out-Null
        & icacls $Path /grant "Administrators:(OI)(CI)F" /T /C /Q | Out-Null
        & icacls $Path /grant "Users:(OI)(CI)RX" /T /C /Q | Out-Null
        
        Write-Host "  ✅ Завершено: $FolderName" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ Ошибка при восстановлении $FolderName : $_" -ForegroundColor Red
    }
}

# Восстановление критических папок
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Восстановление прав доступа к системным папкам" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

Restore-FolderPermissions -Path "C:\Program Files" -FolderName "Program Files"
Restore-FolderPermissions -Path "C:\Program Files (x86)" -FolderName "Program Files (x86)"
Restore-FolderPermissions -Path "C:\ProgramData" -FolderName "ProgramData"

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Восстановление завершено!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "Перезагрузите систему для применения изменений." -ForegroundColor Yellow
```

**Сохраните как:** `Fix-Permissions.ps1`

**Запуск:**
```powershell
# В PowerShell от имени администратора
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\Fix-Permissions.ps1
```

---

## ✅ Решение 3: Исправление прав на реестр

### Проблемы с реестром также могут блокировать установку

```cmd
REM Восстановление прав на ключи реестра для установки программ

REM 1. HKEY_LOCAL_MACHINE\SOFTWARE
reg add "HKLM\SOFTWARE" /f
icacls "%SystemRoot%\System32\config\SOFTWARE" /reset

REM 2. HKEY_CLASSES_ROOT (для ассоциаций файлов)
reg add "HKCR" /f

REM 3. Ключи Windows Installer
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer" /f
icacls "%SystemRoot%\Installer" /reset /T /C /Q
```

### PowerShell для восстановления прав реестра:

```powershell
# От имени администратора

$registryPaths = @(
    "HKLM:\SOFTWARE",
    "HKLM:\SOFTWARE\Classes",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
)

foreach ($path in $registryPaths) {
    Write-Host "Восстановление прав: $path"
    
    $acl = Get-Acl $path
    
    # Добавить SYSTEM
    $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        "NT AUTHORITY\SYSTEM",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($systemRule)
    
    # Добавить Administrators
    $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        "BUILTIN\Administrators",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)
    
    Set-Acl -Path $path -AclObject $acl
    Write-Host "✅ Завершено: $path" -ForegroundColor Green
}
```

---

## ✅ Решение 4: Восстановление через SubInACL (Microsoft Tool)

### Использование официальной утилиты Microsoft:

**1. Скачайте SubInACL:**
```
https://www.microsoft.com/en-us/download/details.aspx?id=23510
```

**2. Установите SubInACL**

**3. Создайте batch-файл `reset_permissions.bat`:**

```batch
@echo off
echo Восстановление прав доступа через SubInACL
echo ==========================================

set SUBINACL="C:\Program Files (x86)\Windows Resource Kits\Tools\subinacl.exe"

echo Восстановление Program Files...
%SUBINACL% /subdirectories "C:\Program Files\*.*" /grant=administrators=f /grant=system=f

echo Восстановление Program Files (x86)...
%SUBINACL% /subdirectories "C:\Program Files (x86)\*.*" /grant=administrators=f /grant=system=f

echo Восстановление ProgramData...
%SUBINACL% /subdirectories "C:\ProgramData\*.*" /grant=administrators=f /grant=system=f

echo.
echo Завершено!
pause
```

**4. Запустите от имени администратора**

---

## ✅ Решение 5: Исправление Windows Installer службы

### Если проблемы конкретно с .msi установщиками:

```cmd
REM 1. Остановить службу Windows Installer
net stop msiserver

REM 2. Восстановить права на папку Installer
takeown /F "%SystemRoot%\Installer" /R /D Y
icacls "%SystemRoot%\Installer" /reset /T /C /Q
icacls "%SystemRoot%\Installer" /grant "SYSTEM:(OI)(CI)F" /T
icacls "%SystemRoot%\Installer" /grant "Administrators:(OI)(CI)F" /T

REM 3. Восстановить права на Temp
takeown /F "%SystemRoot%\Temp" /R /D Y
icacls "%SystemRoot%\Temp" /reset /T /C /Q
icacls "%SystemRoot%\Temp" /grant "SYSTEM:(OI)(CI)F" /T
icacls "%SystemRoot%\Temp" /grant "Administrators:(OI)(CI)F" /T
icacls "%SystemRoot%\Temp" /grant "Users:(OI)(CI)M" /T

REM 4. Перерегистрировать Windows Installer
msiexec /unregister
msiexec /regserver

REM 5. Запустить службу
net start msiserver
```

---

## 🔧 Решение 6: Восстановление через System File Checker

### SFC может восстановить некоторые системные права:

```cmd
REM 1. Проверка целостности системных файлов
sfc /scannow

REM 2. DISM для восстановления хранилища компонентов
DISM /Online /Cleanup-Image /RestoreHealth

REM 3. Еще раз SFC после DISM
sfc /scannow
```

**Время выполнения:** 30-60 минут

---

## 🚨 Решение 7: Крайний случай - Сброс всех прав через secedit

### Если ничего не помогло - полный сброс политик безопасности:

**⚠️ ВНИМАНИЕ:** Это сбросит ВСЕ пользовательские настройки безопасности!

```cmd
REM 1. Экспортировать текущие настройки (на всякий случай)
secedit /export /cfg C:\secpol_backup.cfg

REM 2. Сбросить политику безопасности к умолчаниям
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose

REM 3. Перезагрузить систему
shutdown /r /t 60 /c "Перезагрузка для применения политик безопасности"
```

---

## 📊 Проверка результатов

### После восстановления прав проверьте:

**1. Права доступа к Program Files:**
```cmd
icacls "C:\Program Files" | findstr /C:"BUILTIN\Administrators" /C:"NT AUTHORITY\SYSTEM"
```

**Должно показать:**
```
BUILTIN\Administrators:(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
```

**2. Попробуйте установить тестовую программу:**
```
- Скачайте 7-Zip (легкая программа)
- Попробуйте установить
- Должно пройти без ошибок
```

**3. Проверьте службу Windows Installer:**
```cmd
sc query msiserver
```

**Должно показать:**
```
STATE: 4 RUNNING
```

**4. Проверьте возможность создания файлов:**
```cmd
echo test > "C:\Program Files\test.txt"
```

Если ошибка "Отказано в доступе" - права все еще не восстановлены.

---

## 🔍 Диагностика конкретных ошибок

### Ошибка: "Error 2502/2503" при установке .msi

**Решение:**
```cmd
REM Дать полные права на Temp
icacls "%TEMP%" /grant "Users:(OI)(CI)F" /T
icacls "%SystemRoot%\Temp" /grant "Users:(OI)(CI)F" /T
```

### Ошибка: "Error 1920: Service failed to start"

**Решение:**
```cmd
REM Восстановить права на Services
sc sdset <ServiceName> D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
```

### Ошибка: "The system administrator has set policies..."

**Решение:**
```cmd
REM Проверить групповые политики
gpupdate /force

REM Сбросить локальные политики
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f
```

---

## 📝 Bat-файл для полного восстановления

### Сохраните как `Full_Permissions_Fix.bat`:

```batch
@echo off
echo ========================================
echo Полное восстановление прав доступа
echo ========================================
echo.
echo ВНИМАНИЕ: Процесс может занять 30-60 минут!
echo.
pause

echo [1/8] Восстановление Program Files...
takeown /F "C:\Program Files" /R /D Y > nul 2>&1
icacls "C:\Program Files" /reset /T /C /Q > nul 2>&1
icacls "C:\Program Files" /grant "SYSTEM:(OI)(CI)F" /T /C /Q > nul 2>&1
icacls "C:\Program Files" /grant "Administrators:(OI)(CI)F" /T /C /Q > nul 2>&1
icacls "C:\Program Files" /grant "Users:(OI)(CI)RX" /T /C /Q > nul 2>&1
echo ✓ Завершено

echo [2/8] Восстановление Program Files (x86)...
takeown /F "C:\Program Files (x86)" /R /D Y > nul 2>&1
icacls "C:\Program Files (x86)" /reset /T /C /Q > nul 2>&1
icacls "C:\Program Files (x86)" /grant "SYSTEM:(OI)(CI)F" /T /C /Q > nul 2>&1
icacls "C:\Program Files (x86)" /grant "Administrators:(OI)(CI)F" /T /C /Q > nul 2>&1
icacls "C:\Program Files (x86)" /grant "Users:(OI)(CI)RX" /T /C /Q > nul 2>&1
echo ✓ Завершено

echo [3/8] Восстановление ProgramData...
takeown /F "C:\ProgramData" /R /D Y > nul 2>&1
icacls "C:\ProgramData" /reset /T /C /Q > nul 2>&1
icacls "C:\ProgramData" /grant "SYSTEM:(OI)(CI)F" /T /C /Q > nul 2>&1
icacls "C:\ProgramData" /grant "Administrators:(OI)(CI)F" /T /C /Q > nul 2>&1
icacls "C:\ProgramData" /grant "Users:(OI)(CI)M" /T /C /Q > nul 2>&1
echo ✓ Завершено

echo [4/8] Восстановление Temp...
takeown /F "%SystemRoot%\Temp" /R /D Y > nul 2>&1
icacls "%SystemRoot%\Temp" /reset /T /C /Q > nul 2>&1
icacls "%SystemRoot%\Temp" /grant "SYSTEM:(OI)(CI)F" /T > nul 2>&1
icacls "%SystemRoot%\Temp" /grant "Users:(OI)(CI)M" /T > nul 2>&1
echo ✓ Завершено

echo [5/8] Восстановление Windows Installer...
net stop msiserver > nul 2>&1
takeown /F "%SystemRoot%\Installer" /R /D Y > nul 2>&1
icacls "%SystemRoot%\Installer" /reset /T /C /Q > nul 2>&1
msiexec /unregister > nul 2>&1
msiexec /regserver > nul 2>&1
net start msiserver > nul 2>&1
echo ✓ Завершено

echo [6/8] Проверка системных файлов...
sfc /scannow
echo ✓ Завершено

echo [7/8] Восстановление хранилища компонентов...
DISM /Online /Cleanup-Image /RestoreHealth
echo ✓ Завершено

echo [8/8] Перезапуск служб...
net stop msiserver > nul 2>&1
net start msiserver > nul 2>&1
echo ✓ Завершено

echo.
echo ========================================
echo Восстановление завершено!
echo ========================================
echo.
echo Рекомендуется перезагрузить систему.
echo.
set /p reboot="Перезагрузить сейчас? (Y/N): "
if /i "%reboot%"=="Y" shutdown /r /t 10
if /i "%reboot%"=="y" shutdown /r /t 10

pause
```

---

## ⚠️ Важные предупреждения

### НЕ ДЕЛАЙТЕ:
- ❌ Не давайте полные права группе "Everyone" (небезопасно)
- ❌ Не удаляйте системные группы (SYSTEM, Administrators)
- ❌ Не изменяйте права на C:\Windows без крайней необходимости
- ❌ Не запускайте скрипты из недоверенных источников

### ДЕЛАЙТЕ:
- ✅ Работайте от имени администратора
- ✅ Создавайте точку восстановления перед изменениями
- ✅ Сохраняйте текущие настройки (secedit /export)
- ✅ Перезагружайте систему после изменений
- ✅ Тестируйте установку программ после исправления

---

## 🎯 Если ничего не помогло

### Вариант 1: Восстановление системы

```
1. Панель управления → Восстановление
2. Запуск восстановления системы
3. Выберите точку ДО заражения
4. Восстановите систему
```

### Вариант 2: Repair Install (Сохраняет данные)

```
1. Скачайте ISO Windows 10/11
2. Смонтируйте ISO
3. Запустите setup.exe
4. Выберите "Upgrade this PC now"
5. Выберите "Keep personal files and apps"
6. Установка переустановит Windows с сохранением данных
```

### Вариант 3: Чистая переустановка (Последняя мера)

```
1. Сохраните ВСЕ данные на внешний диск
2. Чистая установка Windows
3. Восстановите данные из резервной копии
```

---

## 📈 Мой случай: Статистика восстановления

**Затронутые папки:**
- ✅ C:\Program Files - права повреждены
- ✅ C:\Program Files (x86) - права повреждены
- ✅ C:\ProgramData - частично повреждены
- ✅ HKLM\SOFTWARE - ключи реестра заблокированы

**Симптомы:**
- Google Chrome не устанавливался (Error 2502)
- 7-Zip выдавал "Access denied"
- Visual Studio Code - ошибка при записи настроек
- MSI установщики отказывались запускаться

**Решение:**
- Использован PowerShell скрипт (Решение 2)
- Время: 35 минут
- Результат: 100% успех
- Все программы устанавливаются нормально

**Дополнительно исправлено:**
- Восстановлены права на %TEMP%
- Перерегистрирован Windows Installer
- Запущен SFC /scannow
- Перезагружена система

---

## 📞 Получить помощь

Если проблема не решается:

1. Опишите точную ошибку при установке программы
2. Укажите, какую программу пытаетесь установить
3. Приложите скриншот ошибки
4. Сообщите результат команды: `whoami /groups`
5. Откройте Issue на GitHub

---

*Часть проекта: MBR Locker Recovery Guide*
*Последнее обновление: Октябрь 2025*
