$ErrorActionPreference = 'Stop'
$project = $PSScriptRoot
$cache = Join-Path $env:LOCALAPPDATA 'ProxyRouteBuild'
if (!(Get-Command go -ErrorAction SilentlyContinue)) {
    $env:Path = (Join-Path $cache 'go\bin') + ';' + $env:Path
}
if ($env:JAVA_HOME) { $env:Path = (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:Path }
if (!$env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
if (!$env:ANDROID_NDK_HOME) {
    $ndk = Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (!$ndk) { throw 'Install Android NDK r27 or set ANDROID_NDK_HOME' }
    $env:ANDROID_NDK_HOME = $ndk.FullName
}
$env:GOBIN = Join-Path $cache 'bin'
$env:Path = $env:GOBIN + ';' + $env:Path
$env:CGO_LDFLAGS = '-Wl,-z,max-page-size=16384'
$mobile = 'v0.0.0-20250520180527-a1d90793fc63'
go install "golang.org/x/mobile/cmd/gomobile@$mobile"
if ($LASTEXITCODE) { throw 'gomobile install failed' }
go install "golang.org/x/mobile/cmd/gobind@$mobile"
if ($LASTEXITCODE) { throw 'gobind install failed' }
New-Item -ItemType Directory -Force (Join-Path $project 'app\libs') | Out-Null
Push-Location (Join-Path $project 'native')
try {
    $bindArgs = @('bind','-target=android/arm64,android/amd64,android/arm','-androidapi','29',
        '-javapkg','dev.proxyroute.nativecore','-ldflags','-s -w','-o','../app/libs/tunnel.aar','./tunnel')
    & gomobile @bindArgs
    if ($LASTEXITCODE) { throw 'Native Android build failed' }
} finally {
    Pop-Location
}
