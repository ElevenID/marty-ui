$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'native-credential-chooser.cpp'
$output=Join-Path $PSScriptRoot '../artifacts/native-credential-chooser'
[void](New-Item -ItemType Directory -Force $output)
$output=(Resolve-Path $output).Path
$vswhere='C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe'
$installation=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if($LASTEXITCODE -ne 0 -or -not $installation){throw 'MSVC unavailable'}
$version=Get-ChildItem (Join-Path $installation 'VC/Tools/MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
$sdk='C:/Program Files (x86)/Windows Kits/10'
$sdkVersion='10.0.26100.0'
$compiler=Join-Path $version.FullName 'bin/Hostx64/x64/cl.exe'
$priorInclude=$env:INCLUDE;$priorLib=$env:LIB
try {
  $env:INCLUDE=@((Join-Path $version.FullName 'include'),"$sdk/Include/$sdkVersion/ucrt","$sdk/Include/$sdkVersion/shared","$sdk/Include/$sdkVersion/um","$sdk/Include/$sdkVersion/winrt") -join ';'
  $env:LIB=@((Join-Path $version.FullName 'lib/x64'),"$sdk/Lib/$sdkVersion/ucrt/x64","$sdk/Lib/$sdkVersion/um/x64") -join ';'
  $exe=Join-Path $output 'native-credential-chooser.exe'
  & $compiler /nologo /EHsc /std:c++17 /W4 /WX /DUNICODE /D_UNICODE $source "/Fe:$exe" "/Fo:$output/chooser.obj" /link ole32.lib oleaut32.lib uiautomationcore.lib
  if($LASTEXITCODE -ne 0){throw 'Native helper build failed'}
  $proof=& $exe --self-test
  if($LASTEXITCODE -ne 0){throw 'Native helper self-test failed'}
  $metadata=@{source_sha256=(Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant();binary_sha256=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant();sdk_version=$sdkVersion;compiler_version=$version.Name;self_test=($proof|ConvertFrom-Json);scope='Unsigned engineering helper; no chooser observed or invoked'}
  $metadata | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $output 'build.json')
  $metadata | ConvertTo-Json -Depth 5 -Compress
}finally{$env:INCLUDE=$priorInclude;$env:LIB=$priorLib}
