using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// How a read-back reports each way the token can fail it. Each read-back path keeps the exceptions
/// its callers have always seen; the flow behind them is <see cref="SecretReadBack.Read"/>.
/// </summary>
/// <param name="Unreadable">The ephemeral key's <c>CKA_VALUE</c> could not be read.</param>
/// <param name="WrongLength">The value was not the expected length: (actual, expected).</param>
/// <param name="DestroyFailed">
/// Wraps a <c>C_DestroyObject</c> failure after an otherwise successful read, or <see langword="null"/> to
/// let it surface as it is.
/// </param>
internal sealed record ReadBackFailures(
    Func<Exception> Unreadable,
    Func<int, int, Exception> WrongLength,
    Func<Pkcs11Exception, Exception>? DestroyFailed = null)
{
    /// <summary>The KDF adapters' failures (<c>HkdfPkcs11</c>, <c>SP800108HmacCounterKdfPkcs11</c>, PBKDF2, <c>DeriveBytes</c>).</summary>
    internal static ReadBackFailures KdfOutput { get; } = new(
        () => new InvalidOperationException(
            "Derived key did not expose CKA_VALUE; the token may not permit reading derived key material."),
        // A token that ignores CKA_VALUE_LEN would hand back a truncated or oversized key.
        (actual, expected) => new CryptographicException(
            $"The token returned {actual} bytes of derived key material; {expected} were requested."));
}

/// <summary>
/// An open read-back of one kind of secret, from <see cref="Pkcs11Session.BeginReadBack"/>: the only way the
/// library reads secret key material off the token. The policy allowed the kind before this was created; while it
/// is open the session is held exclusively, and the templates and key-agreement KDFs it judges are tagged as this
/// read-back (<c>KeyTemplateRequest.ReadBackFor</c>). Dispose it when the read is done.
/// </summary>
/// <param name="reportExport">Logs the export; called once a value has been read, checked and its key destroyed.</param>
/// <param name="session">The session's half of the read-back (the tag and the exclusive lease), released on dispose.</param>
internal sealed class SecretReadBack(Action reportExport, IDisposable session) : IDisposable
{

    /// <summary>
    /// Creates the ephemeral, extractable key holding the secret, reads its <c>CKA_VALUE</c>, checks it and
    /// destroys the key: the single read-back flow behind every byte-returning path.
    /// </summary>
    /// <param name="createEphemeral">Creates the key on the token; its templates are judged as this read-back.</param>
    /// <param name="expectedLength">The length the value must have.</param>
    /// <param name="failures">How the calling path reports a failure.</param>
    /// <param name="check">Further checks on the value (it is zeroed if one throws), or <see langword="null"/>.</param>
    /// <returns>The value, owned by the caller, who should zero it once done.</returns>
    /// <remarks>
    /// The value is zeroed on every failure, including a failed destroy after a good read: a secret is never
    /// left behind in managed memory alongside an exception. A destroy failure is swallowed only while an
    /// earlier failure is propagating, which it would otherwise replace; the key is a session object, which
    /// the token collects at <c>C_CloseSession</c> either way. The export is logged only once the value is
    /// in hand and the ephemeral key gone.
    /// </remarks>
    internal byte[] Read(Func<Pkcs11Key> createEphemeral, int expectedLength, ReadBackFailures failures, Action<byte[]>? check = null)
    {
        Pkcs11Key ephemeral = createEphemeral();
        byte[] value;
        using (ephemeral)
        {
            value = ReadValue(ephemeral, expectedLength, failures, check);
            try
            {
                ephemeral.Destroy();
            }
            catch (Pkcs11Exception ex)
            {
                CryptographicOperations.ZeroMemory(value);
                if (failures.DestroyFailed is { } wrap)
                    throw wrap(ex);
                throw;
            }
        }

        reportExport();
        return value;
    }

    // Reads and checks the value; on any failure zeroes what was read and destroys the key best-effort.
    private static byte[] ReadValue(Pkcs11Key ephemeral, int expectedLength, ReadBackFailures failures, Action<byte[]>? check)
    {
        byte[]? value = null;
        try
        {
            // The attribute owns an unmanaged copy of the secret; disposing it zeroizes that copy.
            using (var attrs = ephemeral.GetAttributeValue(CKA.CKA_VALUE))
            {
                if (attrs.Count == 0 || attrs[0].CannotBeRead)
                    throw failures.Unreadable();
                value = attrs[0].GetValueAsByteArray();
            }

            if (value.Length != expectedLength)
                throw failures.WrongLength(value.Length, expectedLength);
            check?.Invoke(value);
            return value;
        }
        catch
        {
            if (value is not null)
                CryptographicOperations.ZeroMemory(value);
            DestroyAfterFailure(ephemeral);
            throw;
        }
    }

    // A throw from here would replace the exception the read-back is already unwinding with.
    private static void DestroyAfterFailure(Pkcs11Key ephemeral)
    {
        try
        {
            ephemeral.Destroy();
        }
        catch (Pkcs11Exception)
        {
            // Deliberately swallowed: see Read's remarks. The primary exception is the useful one.
        }
    }

    /// <summary>Closes the read-back and releases the session.</summary>
    public void Dispose() => session.Dispose();
}
