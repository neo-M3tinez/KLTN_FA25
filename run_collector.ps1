# Kibana Alert Collector - PowerShell Wrapper
# Author: Sp4c3K

param(
    [Parameter(Mandatory=$false)]
    [string]$KibanaUrl = $env:KIBANA_URL,
    
    [Parameter(Mandatory=$false)]
    [string]$Username = $env:KIBANA_USERNAME,
    
    [Parameter(Mandatory=$false)]
    [string]$Password = $env:KIBANA_PASSWORD,
    
    [Parameter(Mandatory=$false)]
    [string]$ApiKey = $env:KIBANA_API_KEY,
    
    [Parameter(Mandatory=$false)]
    [string]$Space = "default",
    
    [Parameter(Mandatory=$false)]
    [int]$Interval = 60,
    
    [Parameter(Mandatory=$false)]
    [switch]$Process,
    
    [Parameter(Mandatory=$false)]
    [switch]$Test,
    
    [Parameter(Mandatory=$false)]
    [switch]$LoadEnv
)

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Kibana Alert Collector - Sp4c3K                      ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Load environment file if requested
if ($LoadEnv -and (Test-Path "config.env")) {
    Write-Host "📋 Loading configuration from config.env..." -ForegroundColor Yellow
    Get-Content "config.env" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($value -and $key -notmatch '^#') {
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
                Write-Host "   ✓ $key set" -ForegroundColor Green
            }
        }
    }
    
    # Re-read variables
    $KibanaUrl = $env:KIBANA_URL
    $Username = $env:KIBANA_USERNAME
    $Password = $env:KIBANA_PASSWORD
    $ApiKey = $env:KIBANA_API_KEY
}

# Validate inputs
if (-not $KibanaUrl) {
    Write-Host "❌ Error: Kibana URL is required!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\run_collector.ps1 -KibanaUrl http://localhost:5601 -Username elastic -Password changeme" -ForegroundColor Gray
    Write-Host "  .\run_collector.ps1 -LoadEnv  # Load from config.env" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

if (-not $ApiKey -and (-not $Username -or -not $Password)) {
    Write-Host "❌ Error: Authentication required!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Provide either:" -ForegroundColor Yellow
    Write-Host "  1. -Username and -Password" -ForegroundColor Gray
    Write-Host "  2. -ApiKey" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# Build command
$cmd = "python kibana_collector.py --url `"$KibanaUrl`" --space `"$Space`" --interval $Interval"

if ($ApiKey) {
    $cmd += " --api-key `"$ApiKey`""
    $authMethod = "API Key"
} else {
    $cmd += " --username `"$Username`" --password `"$Password`""
    $authMethod = "Username/Password"
}

if ($Process) {
    $cmd += " --process"
    $processingMode = "Yes (with Agent Planner)"
} else {
    $processingMode = "No (collect only)"
}

if ($Test) {
    $cmd += " --test"
}

# Display configuration
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Kibana URL: $KibanaUrl" -ForegroundColor White
Write-Host "  Space: $Space" -ForegroundColor White
Write-Host "  Auth Method: $authMethod" -ForegroundColor White
Write-Host "  Poll Interval: ${Interval}s" -ForegroundColor White
Write-Host "  Process Alerts: $processingMode" -ForegroundColor White
Write-Host ""

if ($Test) {
    Write-Host "🧪 Running connection test..." -ForegroundColor Yellow
} else {
    Write-Host "🚀 Starting collector..." -ForegroundColor Green
    Write-Host "   Press Ctrl+C to stop" -ForegroundColor Gray
}
Write-Host ""

# Run collector
try {
    Invoke-Expression $cmd
} catch {
    Write-Host ""
    Write-Host "❌ Error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "👋 Collector stopped" -ForegroundColor Yellow
