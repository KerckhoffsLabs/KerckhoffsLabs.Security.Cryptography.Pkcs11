; Analyzer release tracking (https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md)
; Rules move from Unshipped to Shipped when a release goes out, so a shipped id can never change meaning.

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|------
KLPKCS11008 | Security | Warning | InsecureRsaPaddingAnalyzer, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11008
KLPKCS11009 | Security | Warning | InsecureMechanismAnalyzer, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11009
KLPKCS11010 | Security | Warning | BrokenHashAnalyzer, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11010
KLPKCS11011 | Interop | Error | DispatchModel, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11011
KLPKCS11012 | Interop | Error | DispatchModel, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11012
KLPKCS11013 | Interop | Error | DispatchModel, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11013
KLPKCS11014 | Interop | Error | DispatchModel, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11014
KLPKCS11015 | Interop | Error | DispatchModel, https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#KLPKCS11015
