# expatride-management-tool

$u = "https://raw.githubusercontent.com/nubrixsecurity/expatride-management-tool/main/start.ps1"
$p = Join-Path $env:TEMP "start.ps1"
Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
Invoke-Item "C:\ProgramData\Nubrix\AdminTool\Config\"
