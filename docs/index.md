---
_layout: landing
title: Secure-by-default PKCS#11 for .NET
---

<section class="kl-hero">
<img class="kl-hero-logo" src="images/icon.png" alt="" />
<div><span class="kl-eyebrow">PKCS#11 v3.2 &middot; .NET 10</span></div>
<h1>Secure-by-default PKCS#11 for .NET</h1>
<p class="kl-lead">KerckhoffsLabs.Security.Cryptography.Pkcs11 wraps your HSM, smart card or software token in an
idiomatic .NET API that is hard to hold wrong: keys stay on the token, weak algorithms are refused, and the
adapters drop into code written against <code>System.Security.Cryptography</code>.</p>
<div class="kl-actions">
<a class="btn btn-primary btn-lg" href="guide/getting-started.md">Get started</a>
<a class="btn btn-outline-secondary btn-lg" href="examples/index.md">Browse examples</a>
<a class="btn btn-outline-secondary btn-lg" href="api/index.md">API reference</a>
</div>
<div class="kl-install"><code>dotnet add package KerckhoffsLabs.Security.Cryptography.Pkcs11</code></div>
</section>

<section class="kl-section">
<h2>Why this library</h2>
<p class="kl-sub">PKCS#11 is the standard C API for HSMs, smart cards and software tokens. Calling it from .NET means
marshalling handles, mechanism structs and platform-sized integers, where a wrong layout is silent memory
corruption and a wrong default is a vulnerability.</p>
<div class="kl-grid">
<a class="kl-card" href="guide/crypto-policies.md">
<i class="bi bi-shield-check"></i>
<h3>Secure by default</h3>
<p>Unauthenticated cipher modes, broken hashes, PKCS#1 v1.5 encryption and sub-128-bit curves are refused
before any call reaches the token, and compile-time analyzers flag them.</p>
<span class="kl-more">Crypto policies &rarr;</span>
</a>
<a class="kl-card" href="examples/post-quantum.md">
<i class="bi bi-stars"></i>
<h3>Post-quantum ready</h3>
<p>ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), alongside RSA, ECDSA and the AEAD
suites.</p>
<span class="kl-more">Post-quantum examples &rarr;</span>
</a>
<a class="kl-card" href="examples/index.md">
<i class="bi bi-puzzle"></i>
<h3>BCL-shaped adapters</h3>
<p><code>RSAPkcs11 : RSA</code>, <code>ECDsaPkcs11 : ECDsa</code>, <code>AesGcmPkcs11</code> and friends
drop into code already written against <code>System.Security.Cryptography</code>.</p>
<span class="kl-more">All examples &rarr;</span>
</a>
<a class="kl-card" href="guide/security-model.md">
<i class="bi bi-key"></i>
<h3>Token-resident keys</h3>
<p>Private keys stay sensitive and non-extractable, operations run on the token, and each key gets only the
roles it needs.</p>
<span class="kl-more">Security model &rarr;</span>
</a>
<a class="kl-card" href="guide/getting-started.md">
<i class="bi bi-layers"></i>
<h3>PKCS#11 v3.2, backward-compatible</h3>
<p>One managed API over v2.40, v3.0, v3.1 and v3.2 modules. The calling convention is negotiated for you,
and v3.2-only calls degrade cleanly on older tokens.</p>
<span class="kl-more">Getting started &rarr;</span>
</a>
<a class="kl-card" href="diagnostics.md">
<i class="bi bi-cpu"></i>
<h3>Safe at the boundary</h3>
<p><code>SafeHandle</code>-backed sessions and objects, deterministic disposal, zeroized secret buffers and
the correct <code>CK_ULONG</code> width on every platform. NativeAOT- and trim-compatible.</p>
<span class="kl-more">Analyzer diagnostics &rarr;</span>
</a>
</div>
</section>

<section class="kl-section">
<h2>From a module path to a token key</h2>
<p class="kl-sub">Load the vendor's module, log in, generate a non-extractable AES-256 key on the token, and use it
through an <code>AesGcm</code>-shaped adapter. This snippet is compiled and run against real tokens in CI.</p>
<div class="kl-code">

[!code-csharp[](../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/GettingStarted/GettingStartedExamples.cs#EncryptAndDecryptWithTokenKey)]

</div>
</section>
