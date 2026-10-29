using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// The CBC cases opt in to CKM_AES_CBC on the session (UsePolicy) or reach it through the raw dispatch,
// which the compile-time policy analyzer cannot see, so its warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// The buffer and length conventions the session's calls build on, checked on every real backend: a
/// <c>C_*Final</c> into a buffer too small for its output (§5.2), a final with no update before it, the stream
/// overloads at piece sizes around the block size, an attribute read into a buffer too small for it, a search
/// whose results span more than one page of handles, large random requests, and digests at the lengths where
/// the hash's padding changes shape.
/// </summary>
/// <remarks>
/// The library sizes every output from a length query or a known length and grows the buffer when a module
/// answers <c>CKR_BUFFER_TOO_SMALL</c>; these cases put a real module on each side of those paths.
/// </remarks>
internal static class BufferConventionTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog"u8.ToArray();

    // Not all zeros: Craton HSM refuses an all-zero CBC IV with CKR_MECHANISM_PARAM_INVALID.
    private static readonly byte[] Iv = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];

    private static void WithSession(IPkcs11Backend backend, Action<LowLevelPkcs11Library, NativeCULong, Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    private static void AssertOk(CKR rv, string step) =>
        Assert.True(rv == CKR.CKR_OK, $"{step} was expected to succeed but returned {rv}.");

    private delegate CKR KeyedInit(NativeCULong session, in CK_MECHANISM mechanism, NativeCULong key);

    private static CKR Init(KeyedInit init, NativeCULong sid, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return init(sid, in mech, (NativeCULong)key.ObjectId);
    }

    private delegate (CKR rv, NativeCULong length) FinalCall(Span<byte> buffer, bool lengthOnly);

    // Runs a final into a 1-byte buffer first. It must answer CKR_BUFFER_TOO_SMALL and keep the operation, or
    // show one of the deviations the library tolerates: no length reported (the caller asks again), or the
    // operation ended (the caller starts it again, which start does: Init and every Update). Returns what the
    // final produced at a size it could act on.
    private static byte[] FinalWithAShortBufferFirst(Action start, FinalCall final, Func<int> neededAfterStart)
    {
        start();
        int needed = neededAfterStart();
        byte[] tiny = new byte[1];
        var (rv, reported) = final(tiny, false);
        if (rv == CKR.CKR_OK && needed <= tiny.Length)
            return tiny.AsSpan(0, (int)reported).ToArray();
        Assert.True(rv == CKR.CKR_BUFFER_TOO_SMALL, $"A 1-byte buffer for a final of at least {needed} bytes returned {rv}.");
        Assert.True((ulong)reported >= (ulong)needed || (ulong)reported <= (ulong)tiny.Length,
            $"CKR_BUFFER_TOO_SMALL reported {reported} bytes for a final of at least {needed} bytes.");

        if ((ulong)reported <= (ulong)tiny.Length)
        {
            (rv, reported) = Again(start, () => final([], true));
            AssertOk(rv, "the length query");
        }
        byte[] buffer = new byte[Math.Max((int)(ulong)reported, needed)];
        (rv, NativeCULong written) = Again(start, () => final(buffer, false));
        AssertOk(rv, $"the final with a {buffer.Length}-byte buffer (CKR_BUFFER_TOO_SMALL reported {reported})");
        return buffer.AsSpan(0, (int)written).ToArray();
    }

    private static (CKR rv, NativeCULong length) Again(Action start, Func<(CKR rv, NativeCULong length)> call)
    {
        var result = call();
        if (result.rv != CKR.CKR_OPERATION_NOT_INITIALIZED)
            return result;
        start();
        return call();
    }

    // === C_*Final into a buffer too small ======================================

    public static TheoryData<string> MultipartFinals => ["SHA-256 digest", "ECDSA-SHA256 sign", "AES-GCM encrypt", "AES-GCM decrypt"];

    // A C_*Final given a buffer too small for its output answers CKR_BUFFER_TOO_SMALL with the length it needs,
    // and keeps the operation, so the same final with a large enough buffer completes it (§5.2). The library's
    // stream overloads end every operation this way.
    internal static void Assert_MultipartFinal_BufferTooSmall_KeepsTheOperation(IPkcs11Backend backend, string operation)
    {
        CKM[] needed = operation switch
        {
            "SHA-256 digest" => [CKM.CKM_SHA256],
            "ECDSA-SHA256 sign" => [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256],
            _ => [CKM.CKM_AES_GCM],
        };
        backend.RequireMechanisms(needed);

        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] first = Message.AsSpan(0, 20).ToArray();
            byte[] second = Message.AsSpan(20).ToArray();
            switch (operation)
            {
                case "SHA-256 digest":
                    {
                        void Start()
                        {
                            using var scope = new MechanismParameterScope();
                            CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256).Marshal(scope, out _);
                            AssertOk(lowLevel.C_DigestInit(sid, in mech), "C_DigestInit");
                            AssertOk(lowLevel.C_DigestUpdate(sid, first), "C_DigestUpdate");
                            AssertOk(lowLevel.C_DigestUpdate(sid, second), "C_DigestUpdate");
                        }
                        byte[] digest = FinalWithAShortBufferFirst(Start,
                            (buffer, lengthOnly) => (lowLevel.C_DigestFinal(sid, buffer, lengthOnly, out NativeCULong n), n), () => 32);
                        Assert.Equal(SHA256.HashData(Message), digest);
                        break;
                    }
                case "ECDSA-SHA256 sign":
                    {
                        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
                            void Start()
                            {
                                AssertOk(Init(lowLevel.C_SignInit, sid, mechanism, priv), "C_SignInit");
                                AssertOk(lowLevel.C_SignUpdate(sid, first), "C_SignUpdate");
                                AssertOk(lowLevel.C_SignUpdate(sid, second), "C_SignUpdate");
                            }
                            byte[] signature = FinalWithAShortBufferFirst(Start,
                                (buffer, lengthOnly) => (lowLevel.C_SignFinal(sid, buffer, lengthOnly, out NativeCULong n), n), () => 64);
                            Assert.True(session.Verify(mechanism, pub, Message, signature));
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                default:
                    {
                        bool encrypt = operation == "AES-GCM encrypt";
                        backend.RequireMechanismFlags(CKM.CKM_AES_GCM, f => encrypt ? f.Encrypt : f.Decrypt, encrypt ? "CKF_ENCRYPT" : "CKF_DECRYPT");
                        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
                        ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
                        try
                        {
                            byte[] nonce = RandomNumberGenerator.GetBytes(12);
                            using var aes = new AesGcm(rawKey, 16);
                            byte[] ciphertext = new byte[Message.Length];
                            byte[] tag = new byte[16];
                            aes.Encrypt(nonce, Message, ciphertext, tag);
                            byte[] input = encrypt ? Message : [.. ciphertext, .. tag];
                            byte[] expected = encrypt ? [.. ciphertext, .. tag] : Message;

                            var mechanism = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(nonce, [], 128));
                            var updates = new MemoryStream();
                            void Start()
                            {
                                updates.SetLength(0);
                                AssertOk(Init(encrypt ? lowLevel.C_EncryptInit : lowLevel.C_DecryptInit, sid, mechanism, key), "Init");
                                byte[] part = new byte[input.Length + 16];
                                CKR rv = encrypt
                                    ? lowLevel.C_EncryptUpdate(sid, input, part, lengthOnly: false, out NativeCULong n)
                                    : lowLevel.C_DecryptUpdate(sid, input, part, lengthOnly: false, out n);
                                AssertOk(rv, "Update");
                                updates.Write(part, 0, (int)n);
                            }
                            FinalCall final = encrypt
                                ? (buffer, lengthOnly) => (lowLevel.C_EncryptFinal(sid, buffer, lengthOnly, out NativeCULong n), n)
                                : (buffer, lengthOnly) => (lowLevel.C_DecryptFinal(sid, buffer, lengthOnly, out NativeCULong n), n);

                            // What the final must hold: whatever the update held back, which on encryption is at
                            // least the tag, and on decryption is all the plaintext for a module that releases none
                            // before the tag is checked.
                            byte[] last = FinalWithAShortBufferFirst(Start, final, () => Math.Max(expected.Length - (int)updates.Length, 1));
                            Assert.Equal(expected, (byte[])[.. updates.ToArray(), .. last]);
                        }
                        finally { session.DestroyObject(key); }
                        break;
                    }
            }
        });
    }

    // === A final with no update ================================================

    public static TheoryData<string> EmptyEncryptions => ["AES-CBC", "AES-GCM"];

    // An encryption of nothing, C_EncryptInit straight to C_EncryptFinal, is well defined: AES-CBC without
    // padding gives no bytes, and AES-GCM gives the tag of the empty message. The library's stream overload
    // takes this path for an empty stream. lengthQueryEndsIt records a backend whose length query ends the
    // operation (§5.2 says it must not), so that the final after it answers CKR_OPERATION_NOT_INITIALIZED;
    // refusal records a backend that refuses an empty message at the final with that code.
    internal static void Assert_EncryptFinal_WithNoUpdate_IsTheEmptyMessage(IPkcs11Backend backend, string mode, bool lengthQueryEndsIt = false, CKR? refusal = null)
    {
        CKM mechanismType = mode == "AES-CBC" ? CKM.CKM_AES_CBC : CKM.CKM_AES_GCM;
        backend.RequireMechanismFlags(mechanismType, f => f.Encrypt, "CKF_ENCRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                var mechanism = mode == "AES-CBC"
                    ? new Mechanism(CKM.CKM_AES_CBC, Iv)
                    : new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(nonce, [], 128));
                byte[] expected = [];
                if (mode == "AES-GCM")
                {
                    using var aes = new AesGcm(rawKey, 16);
                    expected = new byte[16];
                    aes.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, expected);
                }

                AssertOk(Init(lowLevel.C_EncryptInit, sid, mechanism, key), "C_EncryptInit");
                AssertOk(lowLevel.C_EncryptFinal(sid, [], lengthOnly: true, out NativeCULong reported), "C_EncryptFinal (length query)");
                Assert.True((int)(ulong)reported >= expected.Length, $"C_EncryptFinal reported {reported} bytes for a {expected.Length}-byte output.");
                byte[] output = new byte[Math.Max((int)(ulong)reported, 1)];
                CKR rv = lowLevel.C_EncryptFinal(sid, output, lengthOnly: false, out NativeCULong written);
                if (refusal is { } refused)
                {
                    Assert.True(rv == refused, $"C_EncryptFinal of an empty message returned {rv}; the module no longer refuses it with {refused}.");
                    return;
                }
                if (lengthQueryEndsIt)
                {
                    Assert.True(rv == CKR.CKR_OPERATION_NOT_INITIALIZED, $"C_EncryptFinal after the length query returned {rv}; the module no longer ends the operation on the query.");
                    return;
                }
                AssertOk(rv, "C_EncryptFinal");
                Assert.Equal(expected, output.AsSpan(0, (int)written).ToArray());

                // The final ended the operation.
                AssertOk(Init(lowLevel.C_EncryptInit, sid, mode == "AES-CBC" ? new Mechanism(CKM.CKM_AES_CBC, Iv) : new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(RandomNumberGenerator.GetBytes(12), [], 128)), key),
                    "C_EncryptInit after C_EncryptFinal");
            }
            finally { session.DestroyObject(key); }
        });
    }

    // An empty stream digests to the hash of the empty message: the stream overload starts the digest and
    // finishes it with no update.
    internal static void Assert_Digest_EmptyStream_IsTheHashOfNothing(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        WithSession(backend, (_, _, session) =>
        {
            using var input = new MemoryStream();
            Assert.Equal(SHA256.HashData([]), session.Digest(new Mechanism(CKM.CKM_SHA256), input, bufferLength: 16));
        });
    }

    // An empty stream verifies against the MAC of the empty message, and against nothing else.
    internal static void Assert_HmacVerify_EmptyStream_IsTheMacOfNothing(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithSession(backend, (_, _, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateGenericSecretKey(session, rawKey);
            try
            {
                var mechanism = new Mechanism(CKM.CKM_SHA256_HMAC);
                byte[] mac = HMACSHA256.HashData(rawKey, (byte[])[]);
                using (var input = new MemoryStream())
                    Assert.True(session.Verify(mechanism, key, input, mac, bufferLength: 16));
                byte[] wrong = [.. mac];
                wrong[0] ^= 0x01;
                using (var input = new MemoryStream())
                    Assert.False(session.Verify(mechanism, key, input, wrong, bufferLength: 16));
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === Stream pieces around the block size ===================================

    public static TheoryData<int> StreamPieceLengths => [1, 15, 17, 4095, 4097];

    // The stream overloads cut the input into pieces of the buffer length and pass each to C_*Update. A block
    // cipher without padding holds back a partial block between updates; the result must not depend on where
    // the pieces fall. Pieces that are not whole blocks: the whole-block ones are an OperationContract case.
    internal static void Assert_StreamCbc_AnyPieceLength_MatchesBcl(IPkcs11Backend backend, int bufferLength)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_CBC, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
        WithSession(backend, (_, _, session) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                using var aes = Aes.Create();
                aes.Key = rawKey;
                foreach (int length in bufferLength == 1 ? (int[])[16, 48] : [16, 48, 4112])
                {
                    // A fresh IV for every encryption: Craton HSM refuses to encrypt twice under one key and IV.
                    byte[] iv = RandomNumberGenerator.GetBytes(16);
                    var mechanism = new Mechanism(CKM.CKM_AES_CBC, iv);
                    byte[] plaintext = RandomNumberGenerator.GetBytes(length);
                    byte[] expected = aes.EncryptCbc(plaintext, iv, PaddingMode.None);

                    using var encrypted = new MemoryStream();
                    using (var input = new MemoryStream(plaintext))
                        session.Encrypt(mechanism, key, input, encrypted, bufferLength);
                    Assert.True(expected.AsSpan().SequenceEqual(encrypted.ToArray()), $"{length} bytes encrypted in {bufferLength}-byte pieces");

                    using var decrypted = new MemoryStream();
                    using (var input = new MemoryStream(expected))
                        session.Decrypt(mechanism, key, input, decrypted, bufferLength);
                    Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.ToArray()), $"{length} bytes decrypted in {bufferLength}-byte pieces");
                }
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === An attribute read into a buffer too small ==============================

    // C_GetAttributeValue with a buffer too small for an attribute answers CKR_BUFFER_TOO_SMALL and sets that
    // attribute's ulValueLen to CK_UNAVAILABLE_INFORMATION (§5.7), all ones at the platform's CK_ULONG width.
    // The library never sends a buffer smaller than the length it asked for, but reads the marker back
    // whenever a module answers this way.
    internal static void Assert_GetAttributeValue_ShortBuffer_IsUnavailableInformation(IPkcs11Backend backend, bool reportsTheNeededLength = false)
    {
        WithSession(backend, (lowLevel, sid, session) =>
        {
            string label = $"kl-short-buffer-{Guid.NewGuid():N}";
            ObjectHandle data = CreateDataObject(session, label, [0x01]);
            try
            {
                // The buffer is larger than the length declared for it, so that a module ignoring ulValueLen
                // writes into memory this case owns rather than past the allocation.
                IntPtr buffer = Marshal.AllocHGlobal(64);
                try
                {
                    CK_ATTRIBUTE[] template = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_LABEL, value = buffer, valueLen = (NativeCULong)1UL }];
                    CKR rv = lowLevel.C_GetAttributeValue(sid, (NativeCULong)data.ObjectId, template);
                    Assert.True(rv == CKR.CKR_BUFFER_TOO_SMALL, $"C_GetAttributeValue with a 1-byte buffer for a {label.Length}-byte label returned {rv}.");
                    // reportsTheNeededLength records a backend that sets the length the attribute needs instead.
                    Assert.Equal(reportsTheNeededLength ? (ulong)label.Length : CK.CK_UNAVAILABLE_INFORMATION, (ulong)template[0].valueLen);
                }
                finally { Marshal.FreeHGlobal(buffer); }

                using var read = session.GetAttributeValue(data, [CKA.CKA_LABEL]);
                Assert.Equal(label, read[0].GetValueAsString());
            }
            finally { session.DestroyObject(data); }
        });
    }

    private static ObjectHandle CreateDataObject(Pkcs11SessionCore session, string label, byte[] value)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
        return session.CreateObject([attrClass, attrToken, attrLabel, attrValue]);
    }

    // === A search over more than one page ======================================

    public static TheoryData<int> SearchResultCounts => [255, 256, 257, 513];

    // The library asks C_FindObjects for 256 handles at a time and calls again while a page comes back full.
    // A search of exactly a page, a page and one, and two pages and one returns every object once.
    internal static void Assert_FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(IPkcs11Backend backend, int count)
    {
        WithSession(backend, (_, _, session) =>
        {
            string label = $"kl-pages-{Guid.NewGuid():N}";
            var created = new List<ObjectHandle>(count);
            try
            {
                for (int i = 0; i < count; i++)
                    created.Add(CreateDataObject(session, label, BitConverter.GetBytes(i)));

                using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
                List<ObjectHandle> found = session.FindAllObjects([attrClass, attrLabel]);

                Assert.Equal(count, found.Count);
                Assert.Equal(
                    created.Select(h => h.ObjectId).Order(),
                    found.Select(h => h.ObjectId).Order());
            }
            finally
            {
                foreach (ObjectHandle handle in created)
                    session.DestroyObject(handle);
            }
        });
    }

    // === Random ================================================================

    public static TheoryData<int> LargeRandomLengths => [100_000, 1 << 20];

    // C_GenerateRandom fills a buffer of any length the caller asks for in one call. Two draws differ, and
    // neither is all zeros.
    // maxRequest records a backend that refuses a longer request with CKR_ARGUMENTS_BAD.
    internal static void Assert_GenerateRandom_Large_FillsTheBuffer(IPkcs11Backend backend, int length, int maxRequest = int.MaxValue)
    {
        WithSession(backend, (_, _, session) =>
        {
            if (length > maxRequest)
            {
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.GenerateRandom(length));
                Assert.Equal(CKR.CKR_ARGUMENTS_BAD, ex.ReturnValue);
                Assert.Equal(maxRequest, session.GenerateRandom(maxRequest).Length);
                return;
            }
            byte[] first = session.GenerateRandom(length);
            byte[] second = session.GenerateRandom(length);
            Assert.Equal(length, first.Length);
            Assert.True(first.AsSpan().ContainsAnyExcept((byte)0), $"A {length}-byte random draw was all zeros.");
            Assert.False(first.AsSpan().SequenceEqual(second), $"Two {length}-byte random draws were equal.");
        });
    }

    // C_SeedRandom either mixes the seed in or says it takes none: CKR_RANDOM_SEED_NOT_SUPPORTED, or
    // CKR_FUNCTION_NOT_SUPPORTED from a module without the function. Either way C_GenerateRandom still works.
    internal static void Assert_SeedRandom_IsTakenOrRefusedCleanly(IPkcs11Backend backend)
    {
        WithSession(backend, (_, _, session) =>
        {
            try
            {
                session.SeedRandom(RandomNumberGenerator.GetBytes(32));
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_RANDOM_SEED_NOT_SUPPORTED or CKR.CKR_FUNCTION_NOT_SUPPORTED)
            {
                // The module takes no seed; nothing changed.
            }
            Assert.Equal(32, session.GenerateRandom(32).Length);
        });
    }

    // === Digests around the hash's block boundaries ============================

    public static TheoryData<CKM> BoundaryDigests => [CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA3_256];

    // The lengths where a hash's final padding changes shape: one byte either side of the point where the
    // length field no longer fits in the last block (55/56 for SHA-256, 111/112 for SHA-512), the block size and
    // its neighbours, a stream piece's size and its neighbours, and a long message. Each is digested in one call
    // and through the stream overload, and compared with the BCL.
    internal static void Assert_Digest_AroundBlockBoundaries_MatchesBcl(IPkcs11Backend backend, CKM mechanism)
    {
        backend.RequireMechanism(mechanism);
        Func<byte[], byte[]> reference = mechanism switch
        {
            CKM.CKM_SHA256 => SHA256.HashData,
            CKM.CKM_SHA384 => SHA384.HashData,
            CKM.CKM_SHA512 => SHA512.HashData,
            _ => SHA3_256.IsSupported ? SHA3_256.HashData : null!,
        };
        if (reference is null)
            Assert.Skip("The host BCL has no SHA3-256.");

        WithSession(backend, (_, _, session) =>
        {
            var digest = new Mechanism(mechanism);
            foreach (int length in (int[])[55, 56, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 135, 136, 137, 4095, 4096, 4097, 1 << 20])
            {
                byte[] data = RandomNumberGenerator.GetBytes(length);
                byte[] expected = reference(data);
                Assert.True(expected.AsSpan().SequenceEqual(session.Digest(digest, data)), $"{mechanism} of {length} bytes in one call");
                using var input = new MemoryStream(data);
                Assert.True(expected.AsSpan().SequenceEqual(session.Digest(digest, input, bufferLength: 4096)), $"{mechanism} of {length} bytes as a stream");
            }
        });
    }
}
