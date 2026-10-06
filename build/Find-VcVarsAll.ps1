# Locates vcvarsall.bat for the C/C++ builds driven from MSBuild targets (pkcs11-mock, the ABI
# probe). Dot-source this file, then call Find-VcVarsAll.
#
# Prefer vswhere (canonical: finds any edition and install path, Build Tools included) and fall
# back to the well-known per-edition paths for older images. Returns $null when none is found.
function Find-VcVarsAll {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null | Select-Object -First 1
        if ($installPath) {
            $cand = Join-Path $installPath 'VC\Auxiliary\Build\vcvarsall.bat'
            if (Test-Path $cand) { return $cand }
        }
    }
    foreach ($ed in 'Enterprise','Professional','Community','BuildTools') {
        $cand = "C:\Program Files\Microsoft Visual Studio\2022\$ed\VC\Auxiliary\Build\vcvarsall.bat"
        if (Test-Path $cand) { return $cand }
    }
    return $null
}
