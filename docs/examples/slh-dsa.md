# SLH-DSA — `SlhDsaPkcs11`

FIPS 205 hash-based signatures; see [Post-quantum cryptography](post-quantum.md) for what the token and
the platform need.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/SlhDsaExamples.cs#SlhDsaSign)]

SLH-DSA's security rests only on its hash function, which makes it the conservative choice for
long-lived signatures (firmware, roots of trust). Its signatures are large and slow to make: the "s"
(small) parameter sets give smaller signatures and slower signing than the "f" (fast) ones. Both
`SlhDsa` and `SlhDsaPkcs11` are `[Experimental]` in .NET 10, so their use is wrapped in
`#pragma warning disable SYSLIB5006`; expect the API to change.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SlhDsaPkcs11>.
