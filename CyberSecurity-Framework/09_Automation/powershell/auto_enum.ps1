# AUTO ENUM - cinco fuentes locales de Windows, sin objetivo remoto.
# Uso: .\auto_enum.ps1 [-OutputDirectory <padre_local_existente>] [-Execute]
# Sin ambos parámetros: solo plan, sin crear directorios ni recolectar.
param(
    [string]$OutputDirectory,
    [switch]$Execute
)

if (-not $Execute -or [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Write-Output 'Plan: sistema, usuarios locales, top20 CPU, netstat -ano y tareas programadas.'
    Write-Output 'Uso: .\auto_enum.ps1 -OutputDirectory C:\destino_existente -Execute'
    if ($Execute) { exit 2 }
    exit 0
}

# Validar cada ancestro, no solo el último componente. No UNC, providers ni
# rutas relativas. Se exige un padre local preexistente y controlado por el
# operador; esto no es un sandbox frente a sustituciones concurrentes de rutas.
function Assert-SafeDirectory {
    param([string]$Path)
    $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (-not $current.PSIsContainer -or
            ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Destino o ancestro no es un directorio normal (reparse point rechazado).'
        }
        if ($current.PSProvider.Name -ne 'FileSystem') { throw 'Solo FileSystem local.' }
        $parent = [IO.Directory]::GetParent($current.FullName)
        if ($null -eq $parent) { break }
        $current = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
    }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'La recolección requiere Windows.'
    }
    if ($OutputDirectory -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Se requiere una ruta absoluta de unidad local; no UNC ni providers.'
    }
    if ($OutputDirectory.Substring(2).Contains(':') -or
        $OutputDirectory -match '(^|[\\/])\.\.([\\/]|$)') {
        throw 'Ruta ambigua o alternate data stream rechazado.'
    }
    $parentPath = [IO.Path]::GetFullPath($OutputDirectory)
    Assert-SafeDirectory $parentPath
} catch {
    Write-Warning "Destino inválido: $($_.Exception.Message)"
    exit 2
}

try {
    $runPath = Join-Path -Path $parentPath -ChildPath ([guid]::NewGuid().ToString()) -ErrorAction Stop
    # Sin -Force: nunca reutilizar ni sobrescribir una ejecución anterior.
    $null = New-Item -Path $runPath -ItemType Directory -ErrorAction Stop
    Assert-SafeDirectory $runPath
} catch {
    Write-Warning "No se pudo crear el run: $($_.Exception.Message)"
    exit 1
}

$blocks = @(
    @{ id = 'system'; file = 'system_info.txt'; collect = { Get-ComputerInfo -ErrorAction Stop } },
    @{ id = 'users'; file = 'local_users.txt'; collect = { Get-LocalUser -ErrorAction Stop } },
    @{ id = 'processes'; file = 'top_processes.txt'; collect = {
        Get-Process -ErrorAction Stop |
            Sort-Object -Property CPU -Descending -ErrorAction Stop |
            Select-Object -First 20 -ErrorAction Stop
    } },
    @{ id = 'connections'; file = 'connections.txt'; collect = { netstat -ano } },
    @{ id = 'tasks'; file = 'scheduled_tasks.txt'; collect = { Get-ScheduledTask -ErrorAction Stop } }
)
$results = @()
$failed = $false
foreach ($block in $blocks) {
    if ($failed) {
        $results += [pscustomobject]@{ id = $block.id; file = $block.file;
            state = 'skipped'; raw_exit = $null; reason = 'Fallo previo; no ejecutado.' }
        continue
    }
    $rawExit = $null
    $outputPath = Join-Path -Path $runPath -ChildPath $block.file -ErrorAction Stop
    $stagingPath = $outputPath + '.partial'
    $writeStarted = $false
    try {
        Assert-SafeDirectory $runPath
        # Recoger antes de abrir salida: un cmdlet que falla no publica un vacío válido.
        $global:LASTEXITCODE = 0
        $data = @(& $block.collect)
        if ($block.id -eq 'connections') {
            $rawExit = $LASTEXITCODE
            if ($rawExit -ne 0) { throw "netstat terminó con rc=$rawExit" }
        }
        Assert-SafeDirectory $runPath
        if (Test-Path -LiteralPath $stagingPath -ErrorAction Stop) { throw 'Salida parcial ya existe.' }
        $writeStarted = $true
        $data | Out-File -LiteralPath $stagingPath -Encoding utf8 -NoClobber -ErrorAction Stop
        Assert-SafeDirectory $runPath
        # File.Move sin overwrite: publicar solo una escritura terminada.
        [IO.File]::Move($stagingPath, $outputPath)
        $results += [pscustomobject]@{ id = $block.id; file = $block.file;
            state = 'success'; raw_exit = $rawExit; reason = 'Fuente completada.' }
    } catch {
        $failed = $true
        $reason = $_.Exception.Message
        Write-Warning "$($block.id): $reason"
        # Retirar solo el archivo parcial propio, tras volver a validar ancestros.
        try {
            Assert-SafeDirectory $runPath
            if ($writeStarted -and (Test-Path -LiteralPath $stagingPath -ErrorAction Stop)) {
                $partial = Get-Item -LiteralPath $stagingPath -Force -ErrorAction Stop
                if ($partial.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw 'No se elimina un archivo sustituido por reparse point.'
                }
                Remove-Item -LiteralPath $stagingPath -ErrorAction Stop
            }
        } catch { Write-Warning "Salida parcial no retirada: $($_.Exception.Message)" }
        $results += [pscustomobject]@{ id = $block.id; file = $block.file;
            state = 'failed'; raw_exit = $rawExit; reason = $reason }
    }
}

$rc = 0
if ($failed) { $rc = 1 }
$summary = [pscustomobject]@{ rc = $rc; run_directory = $runPath; blocks = $results }
$json = $summary | ConvertTo-Json -Depth 5 -ErrorAction Stop
try {
    Assert-SafeDirectory $runPath
    $summaryPath = Join-Path -Path $runPath -ChildPath 'summary.json' -ErrorAction Stop
    $summaryStaging = $summaryPath + '.partial'
    $json | Out-File -LiteralPath $summaryStaging -Encoding utf8 -NoClobber -ErrorAction Stop
    Assert-SafeDirectory $runPath
    [IO.File]::Move($summaryStaging, $summaryPath)
} catch {
    Write-Warning "No se pudo guardar resumen: $($_.Exception.Message)"
    $summary.rc = 1
    $json = $summary | ConvertTo-Json -Depth 5 -ErrorAction Stop
}
Write-Output $json
if ($summary.rc -ne 0) { exit 1 }
exit 0
