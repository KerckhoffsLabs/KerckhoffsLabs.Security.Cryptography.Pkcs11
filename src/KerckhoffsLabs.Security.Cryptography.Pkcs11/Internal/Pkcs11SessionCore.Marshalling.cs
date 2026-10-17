using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    // ---- Marshalling helpers (shared by the wrapper methods) ----

    private const string ValueMustBePositive = "Value has to be positive number";

    /// <summary>
    /// Marshals a managed attribute list into a <c>CK_ATTRIBUTE[]</c> template, returning <see langword="null"/>
    /// (and length 0) when <paramref name="attributes"/> is <see langword="null"/> — the PKCS#11 convention of a
    /// null template meaning "no attributes".
    /// </summary>
    /// <remarks>
    /// <b>Callers must <c>GC.KeepAlive</c> the source collection until after the native call.</b> The
    /// returned array holds raw copies of each attribute's <c>pValue</c> pointer and no reference to
    /// the <see cref="ObjectAttribute"/> that owns the buffer, so once this returns, nothing else
    /// keeps those attributes reachable — and <see cref="ObjectAttribute"/> has a finalizer that
    /// zeroizes and frees. Left unrooted, a caller passing a temporary template can have its buffers
    /// wiped mid-call.
    /// </remarks>
    private static CK_ATTRIBUTE[]? BuildTemplate(List<ObjectAttribute>? attributes)
    {
        if (attributes is null)
            return null;

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = attributes[i].CkAttribute;
        return template;
    }

    /// <summary>
    /// Builds a key-creation template from the caller's <paramref name="attributes"/> followed by the
    /// appended <paramref name="secureDefaults"/>. Returns <see langword="null"/> (length 0) only when both are
    /// empty, matching the "null template = no attributes" convention.
    /// </summary>
    private static CK_ATTRIBUTE[]? BuildTemplateWithDefaults(List<ObjectAttribute>? attributes, ReadOnlyDisposableList<ObjectAttribute> secureDefaults)
    {
        int attrCount = attributes?.Count ?? 0;
        int total = attrCount + secureDefaults.Count;
        if (total == 0)
            return null;

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[total];
        int idx = 0;
        for (int i = 0; i < attrCount; i++)
            template[idx++] = attributes![i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;
        return template;
    }

    /// <summary>
    /// Interprets a verify return value: <see langword="true"/> on <see cref="CKR.CKR_OK"/>, <see langword="false"/> on
    /// <see cref="CKR.CKR_SIGNATURE_INVALID"/> or <see cref="CKR.CKR_SIGNATURE_LEN_RANGE"/> (a signature that is
    /// invalid on its length alone, as SoftHSM2 and Kryoptic report a truncated one), and throws
    /// <see cref="Pkcs11Exception"/> for any other code (tagged with <paramref name="operation"/>).
    /// </summary>
    private static bool IsVerified(CKR rv, string operation)
    {
        if (rv == CKR.CKR_OK) return true;
        if (rv is CKR.CKR_SIGNATURE_INVALID or CKR.CKR_SIGNATURE_LEN_RANGE) return false;
        throw Pkcs11Exception.Create(rv, operation);
    }

    /// <summary>
    /// <see cref="IsVerified(CKR, string)"/>, except that a MAC whose length the mechanism fixes is
    /// <see langword="false"/> at any other <paramref name="signatureLength"/>, whatever the module answered.
    /// </summary>
    /// <remarks>
    /// The module's answer is no use for such a MAC. NSS since 3.126 compares only the first
    /// <c>min(macLen, sigLen)</c> bytes of a non-general HMAC and leaves the length to the caller, so it
    /// answers <see cref="CKR.CKR_OK"/> for a truncated or empty MAC; NSS 3.51 answers a short one with
    /// CKR_DEVICE_ERROR. A key or mechanism error has already surfaced from the init call, which is
    /// checked before this.
    /// </remarks>
    private static bool IsVerified(CKR rv, string operation, CKM mechanism, int signatureLength)
        => (KnownOutputLength.Of(mechanism) is not { } macLength || signatureLength == macLength)
           && IsVerified(rv, operation);

    /// <summary>One step of a Cryptoki two-call length probe: invoke with <paramref name="lengthOnly"/> to
    /// learn the size, then again with the allocated buffer. Capacity comes from the buffer itself, so
    /// the two can never disagree.</summary>
    private delegate CKR LengthProbedCall(Span<byte> buffer, bool lengthOnly, out NativeCULong length);

    /// <summary>
    /// A <see cref="LengthProbedCall"/> that also takes the operation's input. The input is passed in
    /// rather than captured, because a lambda cannot capture a span, and copying it into an array to
    /// capture would leave a plaintext copy on the heap.
    /// </summary>
    private delegate CKR InputLengthProbedCall(ReadOnlySpan<byte> input, Span<byte> buffer, bool lengthOnly, out NativeCULong length);

    /// <summary>
    /// An <see cref="InputLengthProbedCall"/> with two inputs, such as a message's associated data and
    /// payload, passed in for the same reason.
    /// </summary>
    private delegate CKR TwoInputLengthProbedCall(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> buffer, bool lengthOnly, out NativeCULong length);

    /// <inheritdoc cref="CallWithLengthProbe(ReadOnlySpan{byte}, InputLengthProbedCall, string, int?, Func{CKR})"/>
    private static byte[] CallWithLengthProbe(LengthProbedCall call, string operation, int? guess = null)
        => CallWithLengthProbe([], (ReadOnlySpan<byte> _, Span<byte> buffer, bool lengthOnly, out NativeCULong length) => call(buffer, lengthOnly, out length), operation, guess);

    /// <summary>
    /// Runs the PKCS#11 two-call pattern: query the output length, allocate, fill,
    /// and return exactly what the module reports writing.
    /// </summary>
    /// <remarks>
    /// Every length the module reports is checked through <see cref="ReportedLength"/>: one it cannot
    /// have written (larger than the buffer) or cannot mean (<c>CK_UNAVAILABLE_INFORMATION</c>) is
    /// refused, never padded or truncated. A <c>CKR_BUFFER_TOO_SMALL</c> on the fill call leaves the
    /// operation active (PKCS#11 v3.2 §5.2), so it is retried once with the size the module then asks
    /// for. A trimmed buffer is zeroized, since for a decryption it holds plaintext.
    /// </remarks>
    /// <param name="input">The operation's input, passed to every call.</param>
    /// <param name="call">One call into the module.</param>
    /// <param name="operation">The function, for errors.</param>
    /// <param name="guess">
    /// The output length when the mechanism fixes it (<see cref="KnownOutputLength"/>). The output is then
    /// sized up front and filled in one call; a wrong guess is trimmed, or corrected through
    /// <c>CKR_BUFFER_TOO_SMALL</c>.
    /// </param>
    /// <param name="restart">
    /// Starts the operation again, for a module that ends it on <c>CKR_BUFFER_TOO_SMALL</c> against PKCS#11
    /// v3.2 §5.2 (NSS does): the retry then fails with <c>CKR_OPERATION_NOT_INITIALIZED</c>, and the output
    /// is found with a length query on the restarted operation instead.
    /// </param>
    private static byte[] CallWithLengthProbe(ReadOnlySpan<byte> input, InputLengthProbedCall call, string operation,
        int? guess = null, Func<CKR>? restart = null)
        => CallWithLengthProbe(input, [],
            (ReadOnlySpan<byte> first, ReadOnlySpan<byte> _, Span<byte> buffer, bool lengthOnly, out NativeCULong length) => call(first, buffer, lengthOnly, out length),
            operation, guess, restart);

    /// <inheritdoc cref="CallWithLengthProbe(ReadOnlySpan{byte}, InputLengthProbedCall, string, int?, Func{CKR})"/>
    private static byte[] CallWithLengthProbe(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, TwoInputLengthProbedCall call, string operation,
        int? guess = null, Func<CKR>? restart = null)
    {
        if (guess is int guessed)
        {
            byte[] guessBuffer = new byte[guessed];
            CKR filled = call(first, second, guessBuffer, lengthOnly: false, out NativeCULong written);
            if (filled == CKR.CKR_OK)
                return ReportedLength.Trim(guessBuffer, written, operation);
            CryptographicOperations.ZeroMemory(guessBuffer);
            if (filled != CKR.CKR_BUFFER_TOO_SMALL)
                throw Pkcs11Exception.Create(filled, operation);

            // PKCS#11 v3.2 §5.2 has the module report the length it needs, but some leave the length
            // as it was (opencryptoki's ec_sign does). Only a length past the guess was reported; with
            // any other, the operation is still active and the module is asked below.
            if ((ulong)written > (ulong)guessed)
            {
                byte[] sized = new byte[ReportedLength.ForAllocation(written, operation)];
                filled = call(first, second, sized, lengthOnly: false, out written);
                if (filled != CKR.CKR_OPERATION_NOT_INITIALIZED || restart is null)
                {
                    Pkcs11Exception.ThrowIfError(filled, operation);
                    return ReportedLength.Trim(sized, written, operation);
                }
                Pkcs11Exception.ThrowIfError(restart(), operation);
            }
        }

        CKR rv = call(first, second, default, lengthOnly: true, out NativeCULong reported);
        Pkcs11Exception.ThrowIfError(rv, operation);

        byte[] buffer = new byte[ReportedLength.ForAllocation(reported, operation)];
        rv = call(first, second, buffer, lengthOnly: false, out reported);
        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            buffer = new byte[ReportedLength.ForAllocation(reported, operation)];
            rv = call(first, second, buffer, lengthOnly: false, out reported);
        }
        Pkcs11Exception.ThrowIfError(rv, operation);

        return ReportedLength.Trim(buffer, reported, operation);
    }

    /// <summary>
    /// Whether a message-based AEAD keeps its tag in the per-message parameter, so its output is exactly as
    /// long as its input and can be sized without a length query. Some tokens run the whole AEAD on a query,
    /// tag check included, so skipping it also saves that work.
    /// </summary>
    private static bool KeepsTagInTheParameter(CKM mechanism)
        => mechanism is CKM.CKM_AES_GCM or CKM.CKM_AES_CCM or CKM.CKM_CHACHA20_POLY1305;

    /// <summary>
    /// One <c>C_*Update</c> call of a multi-part transform. Every such entry point in Cryptoki has
    /// this shape — input, output, bytes written — which is what lets the five streaming loops share
    /// <see cref="PumpStreamThrough"/>.
    /// </summary>
    private delegate CKR StreamingUpdate(ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen);

    /// <summary>
    /// How many times <see cref="PumpStreamThrough"/> regrows its output for one block before giving up: enough
    /// to double a one-byte buffer past any block or tag a mechanism adds.
    /// </summary>
    private const int MaxUnreportedGrowth = 8;

    /// <summary>
    /// Drives a multi-part transform over a stream: read a block, transform it, write the result,
    /// until the input is exhausted.
    /// </summary>
    /// <remarks>
    /// The output buffer is sized speculatively from <paramref name="bufferLength"/> and grown on
    /// demand, because a mechanism can expand its input (block padding, or an AEAD emitting a tag)
    /// and a token may report the true size only once it has seen the block. <c>CKR_BUFFER_TOO_SMALL</c>
    /// is a length report rather than a failure here: PKCS#11 v3.2 §5.2 requires the operation to stay
    /// active so the same block can be resubmitted, which is why the retry passes the same input
    /// again. A grown buffer is kept for the following blocks rather than re-grown each time.
    /// </remarks>
    private static void PumpStreamThrough(
        Stream inputStream,
        Stream outputStream,
        int bufferLength,
        StreamingUpdate update,
        string operation)
    {
        byte[] input = new byte[bufferLength];
        byte[] output = new byte[bufferLength];
        try
        {
            int bytesRead;
            while ((bytesRead = inputStream.Read(input, 0, input.Length)) > 0)
            {
                CKR rv = update(input.AsSpan(0, bytesRead), output, out NativeCULong outputLen);
                if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, operation);

                // A length no longer than the buffer was not reported (opencryptoki leaves the caller's in
                // place), and an update has no length query of its own here, so the buffer is doubled instead,
                // a bounded number of times.
                for (int grown = 0; rv == CKR.CKR_BUFFER_TOO_SMALL && grown < MaxUnreportedGrowth; grown++)
                {
                    int length = (ulong)outputLen > (ulong)output.Length
                        ? ReportedLength.ForAllocation(outputLen, operation)
                        : checked(output.Length * 2);
                    CryptographicOperations.ZeroMemory(output);
                    output = new byte[length];

                    rv = update(input.AsSpan(0, bytesRead), output, out outputLen);
                }
                Pkcs11Exception.ThrowIfError(rv, operation);

                outputStream.Write(output, 0, ReportedLength.Written(outputLen, output.Length, operation));
            }
        }
        finally
        {
            // One side of the transform is plaintext; neither buffer outlives the call with it.
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    /// <summary>Initializes the non-digest half of a combined operation (<c>C_EncryptInit</c> / <c>C_DecryptInit</c>).</summary>
    private delegate CKR TransformInit(ref CK_MECHANISM mechanism, NativeCULong keyHandle);

    /// <summary>
    /// The non-digest half of a combined digest-and-transform operation: the three native calls that
    /// differ between <see cref="DigestEncrypt(Mechanism, Mechanism, ObjectHandle, Stream, Stream, int)"/>
    /// and <see cref="DecryptDigest(Mechanism, Mechanism, ObjectHandle, Stream, Stream, int)"/>, plus
    /// the <c>CKF_*</c> bit naming that half when an unwind has to cancel it.
    /// </summary>
    private sealed record CombinedTransform(
        TransformInit Init, string InitOperation,
        StreamingUpdate Update, string UpdateOperation,
        LengthProbedCall Final, string FinalOperation,
        ulong CancelFlag);

    /// <summary>
    /// Runs a digest interleaved with a transform over a stream — <c>C_DigestEncryptUpdate</c> and
    /// <c>C_DecryptDigestUpdate</c> are the same algorithm with the roles of the two buffers swapped,
    /// so both directions are driven from here rather than written twice.
    /// </summary>
    /// <remarks>
    /// The digest and the transform are two independent active operations on the session, not one, so
    /// each is finalized separately and the unwind cancels whichever is still live. The transform's
    /// init can fail after the digest's succeeded, which is why the cancel is computed from what
    /// actually completed rather than from where the exception came from.
    /// </remarks>
    /// <returns>The digest over the input, as read by <c>C_DigestFinal</c>.</returns>
    private byte[] DigestAndTransformStream(
        Mechanism digestingMechanism,
        Mechanism transformMechanism,
        ObjectHandle keyHandle,
        Stream inputStream,
        Stream outputStream,
        int bufferLength,
        CombinedTransform transform,
        string operationName)
    {
        // Both mechanisms marshal into the same scope: the two operations run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckDigestingMechanism = digestingMechanism.Marshal(scope, out Pkcs11ParameterBlock? digestParams);

        using var operation = BeginOperation(operationName);
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        CK_MECHANISM ckTransformMechanism = transformMechanism.Marshal(scope, out Pkcs11ParameterBlock? transformParams);

        rv = transform.Init(ref ckTransformMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(transform.CancelFlag, rv, transform.InitOperation);

        PumpStreamThrough(inputStream, outputStream, bufferLength, transform.Update, transform.UpdateOperation);

        // Whatever the transform held back — a partial block, or an AEAD tag.
        byte[] lastPart = CallWithLengthProbe(transform.Final, transform.FinalOperation);
        operation.End(transform.CancelFlag);

        if (lastPart.Length > 0)
            outputStream.Write(lastPart, 0, lastPart.Length);

        byte[] digest = CallWithLengthProbe(
            (Span<byte> buffer, bool lengthOnly, out NativeCULong length) => _pkcs11Library.C_DigestFinal(_sessionId, buffer, lengthOnly, out length),
            OpDigestFinal,
            KnownOutputLength.Of(digestingMechanism.Type));
        operation.Completed();

        digestingMechanism.AbsorbOutput(digestParams);
        transformMechanism.AbsorbOutput(transformParams);

        return digest;
    }
}
