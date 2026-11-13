# Synthetic mocks only. Never invoke an unmocked collection source.
param([string]$ScriptPath, [string]$TestRoot)
$ErrorActionPreference = 'Stop'
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
$tokens = $null
$parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
Assert ($parseErrors.Count -eq 0) "Production AST errors: $parseErrors"
$null = [Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$parseErrors)
Assert ($parseErrors.Count -eq 0) "Fixture AST errors: $parseErrors"
$null = New-Item -Path $TestRoot -ItemType Directory
$source = [IO.File]::ReadAllText($ScriptPath)
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $source = $source.Replace('[Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT', '$false')
    $source = $source.Replace('$OutputDirectory -notmatch ''^[A-Za-z]:[\\/]''', '$false')
}
$copy = Join-Path $TestRoot 'mocked.ps1'
[IO.File]::WriteAllText($copy, $source)
$global:Calls = @()
$global:Fail = ''
function global:Source-Mock([string]$Name) {
    $global:Calls += $Name
    if ($global:Fail -eq 'existing' -and $Name -eq 'system') {
        $run = @(Get-ChildItem -LiteralPath $global:CaseParent -Directory)[0].FullName
        [IO.File]::WriteAllText((Join-Path $run 'system_info.txt'), 'do not delete')
        throw 'Injected source failure with unrelated output'
    }
    if ($global:Fail -eq $Name) { throw "Injected $Name" }
    [pscustomobject]@{ Name = 'synthetic'; CPU = 42 }
}
function global:Get-ComputerInfo { [CmdletBinding()]param() Source-Mock 'system' }
function global:Get-LocalUser { [CmdletBinding()]param() Source-Mock 'users' }
function global:Get-Process { [CmdletBinding()]param() Source-Mock 'processes' }
function global:Get-ScheduledTask { [CmdletBinding()]param() Source-Mock 'tasks' }
function global:netstat {
    Assert ($args.Count -eq 1 -and $args[0] -eq '-ano') 'netstat arguments changed'
    $global:Calls += 'connections'
    $global:LASTEXITCODE = 0
    if ($global:Fail -eq 'connections') { $global:LASTEXITCODE = 7 }
    'synthetic connections'
}
function global:Out-File {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,
        [string]$LiteralPath, [string]$Encoding, [switch]$NoClobber)
    begin { $items = @() }
    process { $items += [string]$InputObject }
    end {
        Assert $NoClobber 'Output must not overwrite'
        Assert (-not [IO.File]::Exists($LiteralPath)) 'Output already exists'
        [IO.File]::WriteAllLines($LiteralPath, [string[]]$items)
        if ($global:Fail -eq 'write' -and $LiteralPath.EndsWith('system_info.txt.partial')) {
            throw 'Injected partial write'
        }
        if ($global:Fail -eq 'summary' -and $LiteralPath.EndsWith('summary.json.partial')) {
            throw 'Injected summary write'
        }
    }
}

# No params, destination only, execute only: no calls or output directory writes.
foreach ($arguments in @(@{}, @{OutputDirectory = (Join-Path $TestRoot 'absent')}, @{Execute = $true})) {
    $global:Calls = @()
    $null = & $copy @arguments
    Assert ($global:Calls.Count -eq 0) 'Implicit collection'
    Assert (-not (Test-Path (Join-Path $TestRoot 'absent'))) 'Implicit directory creation'
}
$null = & $copy -Execute -OutputDirectory (Join-Path $TestRoot 'missing')
Assert ($LASTEXITCODE -eq 2 -and $global:Calls.Count -eq 0) 'Missing parent accepted'
$null = & $copy -Execute -OutputDirectory 'relative'
Assert ($LASTEXITCODE -eq 2 -and $global:Calls.Count -eq 0) 'Relative destination accepted'
$fileParent = Join-Path $TestRoot 'plain-file'
[IO.File]::WriteAllText($fileParent, 'synthetic')
$null = & $copy -Execute -OutputDirectory $fileParent
Assert ($LASTEXITCODE -eq 2 -and $global:Calls.Count -eq 0) 'File accepted as parent'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $target = Join-Path $TestRoot 'link-target'
    $child = Join-Path $target 'child'
    $null = New-Item -ItemType Directory -Path $child
    $link = Join-Path $TestRoot 'linked'
    $null = New-Item -ItemType SymbolicLink -Path $link -Target $target
    foreach ($destination in @($link, (Join-Path $link 'child'))) {
        $null = & $copy -Execute -OutputDirectory $destination
        Assert ($LASTEXITCODE -eq 2 -and $global:Calls.Count -eq 0) 'Reparse path accepted'
    }
    Assert ((Get-ChildItem -LiteralPath $child).Count -eq 0) 'Reparse destination modified'
    $null = & $ScriptPath -Execute -OutputDirectory $target
    Assert ($LASTEXITCODE -eq 2 -and $global:Calls.Count -eq 0) 'Non-Windows guard missing'
}

$ids = @('system', 'users', 'processes', 'connections', 'tasks')
foreach ($failure in @('', 'system', 'users', 'processes', 'connections', 'tasks', 'write', 'summary', 'existing')) {
    $parent = Join-Path $TestRoot ('case-' + [guid]::NewGuid())
    $null = New-Item -ItemType Directory -Path $parent
    $global:Fail = $failure
    $global:CaseParent = $parent
    $global:Calls = @()
    $output = & $copy -OutputDirectory $parent -Execute
    $code = $LASTEXITCODE
    $summary = ($output -join "`n") | ConvertFrom-Json
    Assert ($summary.blocks.Count -eq 5) 'Five summary entries required'
    Assert ($summary.run_directory.StartsWith($parent)) 'Output escaped destination'
    if ($failure -eq '') {
        Assert ($code -eq 0 -and $summary.rc -eq 0) 'Mock success failed'
        Assert (@($summary.blocks | Where-Object state -ne 'success').Count -eq 0) 'Bad success states'
        Assert ($global:Calls.Count -eq 5) 'Sources missing'
        Assert ((Get-ChildItem -LiteralPath $summary.run_directory).Count -eq 6) 'Outputs missing'
    } elseif ($failure -eq 'summary') {
        Assert ($code -eq 1 -and $summary.rc -eq 1) 'Summary failure hidden'
        Assert (-not (Test-Path (Join-Path $summary.run_directory 'summary.json'))) 'Failed summary published'
    } else {
        $index = [array]::IndexOf($ids, $failure)
        if ($failure -in @('write', 'existing')) { $index = 0 }
        Assert ($code -eq 1 -and $summary.rc -eq 1) 'Failure reported as success'
        Assert ($summary.blocks[$index].state -eq 'failed') 'Failed block not marked'
        Assert ($summary.blocks[$index].reason.Length -gt 0) 'Reason missing'
        Assert ($global:Calls.Count -eq ($index + 1)) 'Did not stop at first failure'
        $failedFile = Join-Path $summary.run_directory $summary.blocks[$index].file
        if ($failure -eq 'existing') {
            Assert ([IO.File]::ReadAllText($failedFile) -eq 'do not delete') 'Unrelated file deleted'
        } else {
            Assert (-not (Test-Path $failedFile)) 'Failed output published'
        }
        for ($i = $index + 1; $i -lt 5; $i++) {
            Assert ($summary.blocks[$i].state -eq 'skipped') 'Remaining source not skipped'
        }
        if ($failure -eq 'connections') { Assert ($summary.blocks[3].raw_exit -eq 7) 'Raw rc lost' }
    }
}
Write-Output 'MOCK CONTRACT OK; AST OK'
