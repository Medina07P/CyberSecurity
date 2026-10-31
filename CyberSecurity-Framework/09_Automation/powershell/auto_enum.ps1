# AUTO ENUM - Enumeración en Windows
# Uso: .\auto_enum.ps1

Write-Host "🔍 AUTO ENUM - Windows" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════" -ForegroundColor Cyan

# 1. Información del sistema
Write-Host "`n📋 Sistema" -ForegroundColor Yellow
Get-ComputerInfo | Out-File -FilePath "system_info.txt"

# 2. Usuarios
Write-Host "`n📋 Usuarios" -ForegroundColor Yellow
Get-LocalUser | Out-File -FilePath "local_users.txt"

# 3. Procesos
Write-Host "`n📋 Procesos" -ForegroundColor Yellow
Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 | Out-File -FilePath "top_processes.txt"

# 4. Conexiones de red
Write-Host "`n📋 Conexiones de red" -ForegroundColor Yellow
netstat -ano | Out-File -FilePath "connections.txt"

# 5. Tareas programadas
Write-Host "`n📋 Tareas programadas" -ForegroundColor Yellow
Get-ScheduledTask | Out-File -FilePath "scheduled_tasks.txt"

Write-Host "`n✅ Enumeración completada" -ForegroundColor Green
