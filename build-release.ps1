param(
    [string]$Gradle = 'gradle',
    [switch]$Offline,
    [switch]$SkipNative,
    [switch]$RequireExistingKey
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (!$env:JAVA_HOME) { throw 'Set JAVA_HOME to JDK 17 or 21' }
if (!$env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$env:Path = (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:Path
if (!$SkipNative) { & (Join-Path $root 'build-native.ps1') }

Push-Location $root
try {
    $argsList = @(':app:assembleRelease','--console=plain')
    if ($Offline) { $argsList += '--offline' }
    & $Gradle @argsList
    if ($LASTEXITCODE) { throw 'Android release build failed' }

    $signing = Join-Path $env:LOCALAPPDATA 'ProxyRouteBuild\signing'
    New-Item -ItemType Directory -Force $signing | Out-Null
    $key = Join-Path $signing 'proxyroute.p12'
    $passwordFile = Join-Path $signing 'password.dpapi'
    $tools = Join-Path $env:ANDROID_HOME 'build-tools\35.0.0'
    try {
        if (!(Test-Path $key)) {
            if ($RequireExistingKey) { throw 'Restore the existing ProxyRoute release key before publishing.' }
            if (Test-Path $passwordFile) { throw 'Signing key is missing. Restore it from backup.' }
            $secretBytes = New-Object byte[] 32
            $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $generator.GetBytes($secretBytes) } finally { $generator.Dispose() }
            $secret = [BitConverter]::ToString($secretBytes).Replace('-','')
            $env:PROXYROUTE_SIGN_PASSWORD = $secret
            $pendingKey = Join-Path $signing 'proxyroute-new.p12'
            $keyArgs = @('-genkeypair','-keystore',$pendingKey,'-storetype','PKCS12','-alias','proxyroute',
                '-keyalg','RSA','-keysize','3072','-validity','10000','-dname','CN=ProxyRoute',
                '-storepass:env','PROXYROUTE_SIGN_PASSWORD','-keypass:env','PROXYROUTE_SIGN_PASSWORD')
            & keytool @keyArgs
            if ($LASTEXITCODE) { throw 'Could not generate release key' }
            ConvertTo-SecureString $secret -AsPlainText -Force |
                ConvertFrom-SecureString | Set-Content -Encoding ascii $passwordFile
            Move-Item $pendingKey $key
        } else {
            if (!(Test-Path $passwordFile)) { throw 'Signing password is missing. Restore it from backup.' }
            $secure = Get-Content $passwordFile | ConvertTo-SecureString
            $credential = New-Object System.Management.Automation.PSCredential ('proxyroute',$secure)
            $env:PROXYROUTE_SIGN_PASSWORD = $credential.GetNetworkCredential().Password
        }

        New-Item -ItemType Directory -Force 'dist' | Out-Null
        $metadata = Get-Content -Raw 'app\build\outputs\apk\release\output-metadata.json' | ConvertFrom-Json
        if ($metadata.elements.Count -ne 1) { throw 'Expected a single universal release APK' }
        $version = $metadata.elements[0].versionName
        $apk = "dist\ProxyRoute-$version.apk"
        $aligned = 'dist\aligned-unsigned.apk'
        $unsigned = 'app\build\outputs\apk\release\app-release-unsigned.apk'
        & (Join-Path $tools 'zipalign.exe') -P 16 -f 4 $unsigned $aligned
        if ($LASTEXITCODE) { throw 'APK alignment failed' }
        $signArgs = @('sign','--ks',$key,'--ks-key-alias','proxyroute',
            '--ks-pass','env:PROXYROUTE_SIGN_PASSWORD','--key-pass','env:PROXYROUTE_SIGN_PASSWORD',
            '--v2-signing-enabled','true','--v3-signing-enabled','true','--v4-signing-enabled','false',
            '--out',$apk,$aligned)
        & (Join-Path $tools 'apksigner.bat') @signArgs
        if ($LASTEXITCODE) { throw 'APK signing failed' }
        & (Join-Path $tools 'apksigner.bat') verify --verbose --print-certs $apk
        if ($LASTEXITCODE) { throw 'APK verification failed' }
        & (Join-Path $tools 'zipalign.exe') -c -P 16 4 $apk
        if ($LASTEXITCODE) { throw 'Signed APK failed alignment verification' }
        Remove-Item $aligned
        Get-FileHash -Algorithm SHA256 $apk
    } finally {
        Remove-Item Env:PROXYROUTE_SIGN_PASSWORD -ErrorAction SilentlyContinue
    }
} finally {
    Pop-Location
}
