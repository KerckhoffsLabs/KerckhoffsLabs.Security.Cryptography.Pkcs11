using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The secure-defaults gate does two things: it refuses templates that weaken key protection, and it
/// supplies <c>CKA_SENSITIVE=true</c> / <c>CKA_EXTRACTABLE=false</c> when the caller said nothing. Only
/// the refusals were covered.
/// </summary>
/// <remarks>
/// The gap was found by mutation: rewriting the "did the caller already specify this?" scan so that
/// <c>hasSensitive</c> was computed from <c>CKA_EXTRACTABLE</c> — meaning any template mentioning
/// extractability would suppress the <c>CKA_SENSITIVE</c> default entirely — left the whole suite
/// green. A gate that silently stops adding a default is indistinguishable from one that works, since
/// nothing fails and the key is still created; it is just no longer sensitive. These tests read the
/// template that actually reaches <c>C_GenerateKey</c>.
/// </remarks>
public sealed class SecureDefaultsAreAddedTests
{
    /// <summary>Captures the template the session hands to the module.</summary>
    private sealed class TemplateCapturingFake : FakeLowLevelPkcs11Library
    {
        public readonly List<(ulong Type, byte[] Value)> Captured = [];

        public override CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
        {
            foreach (CK_ATTRIBUTE attribute in template)
            {
                byte[] value = new byte[(int)attribute.valueLen];
                if (value.Length > 0)
                    UnmanagedMemory.Read(attribute.value, value);
                Captured.Add(((ulong)attribute.type, value));
            }

            key = (NativeCULong)1UL;
            return CKR.CKR_OK;
        }
    }

    // The session disposes only the defaults it generates itself; an attribute the caller supplied
    // stays the caller's to free, and each one owns an unmanaged buffer.
    private static List<(ulong Type, byte[] Value)> GenerateWith(params ObjectAttribute[] attributes)
    {
        var fake = new TemplateCapturingFake();
        try
        {
            using var session = new Pkcs11Session(fake, 1);
            session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. attributes]);
        }
        finally
        {
            foreach (ObjectAttribute attribute in attributes)
                attribute.Dispose();
        }
        return fake.Captured;
    }

    private static bool BoolAttribute(List<(ulong Type, byte[] Value)> template, CKA type)
    {
        (ulong Type, byte[] Value) match = Assert.Single(template, a => a.Type == (ulong)type);
        Assert.Single(match.Value); // CK_BBOOL is one byte
        return match.Value[0] != 0;
    }

    [Fact]
    public void CallerSaysNothing_BothDefaultsAreAdded()
    {
        var template = GenerateWith(new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL));

        Assert.True(BoolAttribute(template, CKA.CKA_SENSITIVE));
        Assert.False(BoolAttribute(template, CKA.CKA_EXTRACTABLE));
    }

    /// <summary>
    /// The case the surviving mutation broke: a template that mentions one of the two must still get
    /// the other. Naming <c>CKA_EXTRACTABLE</c> is a normal thing to do — it is how a caller asks for a
    /// wrappable key — and it must not cost them <c>CKA_SENSITIVE</c>.
    /// </summary>
    [Fact]
    public void CallerNamesExtractableOnly_SensitiveIsStillAdded()
    {
        var template = GenerateWith(
            new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL),
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));

        Assert.True(BoolAttribute(template, CKA.CKA_SENSITIVE));
        Assert.True(BoolAttribute(template, CKA.CKA_EXTRACTABLE));  // the caller's value, not the default
    }

    [Fact]
    public void CallerNamesSensitiveOnly_ExtractableIsStillAdded()
    {
        var template = GenerateWith(
            new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL),
            new ObjectAttribute(CKA.CKA_SENSITIVE, true));

        Assert.True(BoolAttribute(template, CKA.CKA_SENSITIVE));
        Assert.False(BoolAttribute(template, CKA.CKA_EXTRACTABLE));
    }

    /// <summary>A caller's explicit choice is never overridden by a default, only supplemented.</summary>
    [Fact]
    public void CallerNamesBoth_NeitherIsDuplicatedNorOverridden()
    {
        var template = GenerateWith(
            new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL),
            new ObjectAttribute(CKA.CKA_SENSITIVE, true),
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));

        // Single() inside the helper is the duplication check: a second copy of either would make the
        // template ambiguous, and which one the token honours is not specified.
        Assert.True(BoolAttribute(template, CKA.CKA_SENSITIVE));
        Assert.True(BoolAttribute(template, CKA.CKA_EXTRACTABLE));
    }
}
