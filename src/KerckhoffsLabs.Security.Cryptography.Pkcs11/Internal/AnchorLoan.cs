namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The anchor session of a token login lent as the working session of a <see cref="Pkcs11Login.OpenSession"/>, on a
/// token that allows no other (<c>CKR_SESSION_COUNT</c>): which anchor, the borrowing core, the library the session
/// came through, and the login generation it was lent in. Kept by the <see cref="TokenLoginRecord"/>, which has at most
/// one loan at a time.
/// </summary>
/// <remarks>
/// A loan is current from <see cref="TokenLoginRecord.TryLend"/> until the borrower is disposed
/// (<see cref="TokenLoginRecord.Return"/>), its library is disposed (<see cref="TokenLoginRecord.ReleaseHoldersOf"/>
/// reclaims it), or the login ends, which closes the anchor and marks the loan <see cref="IsEnded"/>: the borrower then
/// refuses every call.
/// </remarks>
internal sealed class AnchorLoan
{
    private volatile bool _ended;
    private volatile bool _reclaimed;
    private Pkcs11SessionCore? _borrower;

    internal AnchorLoan(Pkcs11SessionCore anchor, Pkcs11Library owner, long generation, ulong sessionHandle)
    {
        Anchor = anchor;
        Owner = owner;
        Generation = generation;
        SessionHandle = sessionHandle;
    }

    /// <summary>The anchor's session handle, for the log.</summary>
    public ulong SessionHandle { get; }

    /// <summary>The anchor lent: the login's own session, which the record alone closes.</summary>
    public Pkcs11SessionCore Anchor { get; }

    /// <summary>The core that works on the anchor for the lent session. Set once, before the loan is recorded.</summary>
    public Pkcs11SessionCore Borrower
    {
        get => _borrower ?? throw new InvalidOperationException("The loan has no borrower yet.");
        internal set => _borrower = value;
    }

    /// <summary>The library the lent session came through; its disposal reclaims the loan.</summary>
    public Pkcs11Library Owner { get; }

    /// <summary>The login generation the anchor was lent in.</summary>
    public long Generation { get; }

    /// <summary>
    /// Whether the login ended while lent, which closed the anchor: the borrower refuses every call, and its return
    /// sends nothing. Set under the record's lock, read without it.
    /// </summary>
    public bool IsEnded => _ended;

    /// <summary>Marks the loan ended; under the record's lock.</summary>
    internal void MarkEnded() => _ended = true;

    /// <summary>
    /// Whether the loan was taken back because <see cref="Owner"/> was disposed
    /// (<see cref="TokenLoginRecord.ReleaseHoldersOf"/>), rather than returned by the borrower's own disposal: the
    /// borrower then refuses every call saying so.
    /// </summary>
    public bool IsReclaimed => _reclaimed;

    /// <summary>Marks the loan reclaimed by its owner's disposal, before the borrower is disposed.</summary>
    internal void MarkReclaimed() => _reclaimed = true;
}
