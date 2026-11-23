param(
 [string]$Compiler='i686-w64-mingw32-g++.exe',
 [string[]]$CompatibleExePaths=@(),
 [string[]]$IncompatibleExePaths=@()
)
$ErrorActionPreference='Stop'
$build=Join-Path $PSScriptRoot 'build'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$flags=@('-std=c++17','-O2','-Wall','-Wextra','-Werror','-static')
$asi=Join-Path $build 'TS2-ObjectLimitFix.asi'
& $Compiler @flags -shared (Join-Path $PSScriptRoot 'CombinedObjectLimitFix.cpp') -o $asi
if($LASTEXITCODE){throw 'ASI compilation failed'}
foreach($name in @('CatalogueIndexFixture','CombinedGuardCheck','GuardBehaviourCheck','ImageCompatibilityCheck')){
 & $Compiler @flags (Join-Path $PSScriptRoot ($name+'.cpp')) -o (Join-Path $build ($name+'.exe'))
 if($LASTEXITCODE){throw "Fixture compilation failed: $name"}
}
& (Join-Path $build 'CatalogueIndexFixture.exe')
if($LASTEXITCODE){throw 'Native index fixture failed'}
& (Join-Path $build 'CombinedGuardCheck.exe') $asi
if($LASTEXITCODE){throw 'Guard/rollback and isolated ASI loader fixture failed'}
& (Join-Path $build 'GuardBehaviourCheck.exe')
if($LASTEXITCODE){throw 'Original guard-equivalence fixture failed'}
foreach($gameExePath in $CompatibleExePaths){
 & (Join-Path $build 'ImageCompatibilityCheck.exe') $gameExePath 'allow'
 if($LASTEXITCODE){throw "Compatible image fixture failed: $gameExePath"}
}
foreach($gameExePath in $IncompatibleExePaths){
 & (Join-Path $build 'ImageCompatibilityCheck.exe') $gameExePath 'reject'
 if($LASTEXITCODE){throw "Incompatible image fixture failed: $gameExePath"}
}
Get-FileHash -LiteralPath $asi -Algorithm SHA256
# The hash above identifies the output download; it is NOT an EXE acceptance rule.
# Supplied EXEs are read as data only; their entry points are never executed.
