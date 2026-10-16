using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Creates a new object
    /// </summary>
    /// <param name="attributes">Object attributes</param>
    /// <returns>Handle of created object</returns>
    public ObjectHandle CreateObject(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "CreateObject");

        // Any object class may arrive here, so the refusal applies but key defaults do not.
        EnforceKeyTemplate(attributes, null);

        NativeCULong objectId = (NativeCULong)CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_CreateObject(_sessionId, template, ref objectId);
        Pkcs11Exception.ThrowIfError(rv, OpCreateObject);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Copies an object, creating a new object for the copy
    /// </summary>
    /// <param name="objectHandle">Handle of object to be copied</param>
    /// <param name="attributes">New values for any attributes of the object that can ordinarily be modified</param>
    /// <returns>Handle of copied object</returns>
    public ObjectHandle CopyObject(ObjectHandle objectHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "CopyObject");

        // A copy can weaken the original's protection, so the same refusal applies.
        EnforceKeyTemplate(attributes, null);


        NativeCULong objectId = (NativeCULong)CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_CopyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, ref objectId);
        Pkcs11Exception.ThrowIfError(rv, OpCopyObject);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="objectHandle">Handle of object to be destroyed</param>
    public void DestroyObject(ObjectHandle objectHandle)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "DestroyObject");


        CKR rv = _pkcs11Library.C_DestroyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDestroyObject);
    }

    /// <summary>
    /// Gets the size of an object in bytes.
    /// </summary>
    /// <param name="objectHandle">Handle of object</param>
    /// <returns>Size of an object in bytes</returns>
    public ulong GetObjectSize(ObjectHandle objectHandle)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetObjectSize");


        NativeCULong objectSize = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetObjectSize(_sessionId, (NativeCULong)(objectHandle.ObjectId), ref objectSize);
        Pkcs11Exception.ThrowIfError(rv, OpGetObjectSize);

        return (ulong)(objectSize);
    }

    /// <summary>
    /// Reads the class, label, id and (when <paramref name="withKeyType"/>) key type of an object in one
    /// <c>C_GetAttributeValue</c> call. Returns <see langword="false"/> whenever that read is not
    /// clean — an unreadable or missing attribute, a value longer than the stack buffers, any return
    /// value but <c>CKR_OK</c> — and the caller then reads through <see cref="GetAttributeValue"/>.
    /// </summary>
    internal bool TryReadIdentity(ObjectHandle objectHandle, bool withKeyType, out ObjectIdentity identity)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "TryReadIdentity");

        return ObjectIdentityReader.TryRead(_pkcs11Library, _sessionId, (NativeCULong)objectHandle.ObjectId, withKeyType, out identity);
    }

    /// <summary>
    /// The most attributes a read lays out on the stack: the template and the two arrays that record
    /// what was allocated for it. A longer read puts them on the heap, so no caller can exhaust the
    /// stack by asking for many attributes.
    /// </summary>
    private const int StackAttributeCount = 16;

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be read</param>
    /// <param name="attributes">Attributes that should be read</param>
    /// <returns>Object attributes, in the order of <paramref name="attributes"/></returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="attributes"/> is empty.</exception>
    public ReadOnlyDisposableList<ObjectAttribute> GetAttributeValue(ObjectHandle objectHandle, ReadOnlySpan<CKA> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetAttributeValue");


        if (attributes.IsEmpty)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        bool onStack = attributes.Length <= StackAttributeCount;
        Span<CK_ATTRIBUTE> template = onStack
            ? stackalloc CK_ATTRIBUTE[StackAttributeCount]
            : new CK_ATTRIBUTE[attributes.Length];
        template = template[..attributes.Length];
        BuildTypeOnlyTemplate(attributes, template);

        // The buffer handed to the module for each attribute, and its size. After every call the
        // template's pointers are reset from here and its lengths checked against it: the module fills
        // the buffers, it never chooses them. An unreadable attribute keeps a null pointer and a zero
        // size, so both start cleared.
        Span<IntPtr> allocatedAt = onStack ? stackalloc IntPtr[StackAttributeCount] : new IntPtr[attributes.Length];
        allocatedAt = allocatedAt[..attributes.Length];
        allocatedAt.Clear();
        Span<NativeCULong> allocatedLen = onStack ? stackalloc NativeCULong[StackAttributeCount] : new NativeCULong[attributes.Length];
        allocatedLen = allocatedLen[..attributes.Length];
        allocatedLen.Clear();

        // Every block handed to the module. Ownership passes to the ObjectAttributes only at the very
        // end, so until then a failure anywhere below has to free them here or they leak — which the
        // fatal-return paths and the malformed-nested-template throw did before this.
        List<IntPtr> allocatedBlocks = new(attributes.Length);

        // Each member of an array attribute: where it sits in its parent's block, and the buffer and
        // size given to it, so the third call is checked the same way. Created only when a read
        // actually returns an array attribute with members.
        List<NestedMember>? nestedMembers = null;

        // First call: determine the size of each attribute value.
        ReadAttributeValues(objectHandle, template);
        AllocateValueBuffers(template, allocatedAt, allocatedLen, allocatedBlocks);

        try
        {
            // Second call: read the values themselves.
            ReadAttributeValues(objectHandle, template);
            RestoreAndGuard(template, allocatedAt, allocatedLen);

            // Third call, needed only if some attribute is an array attribute whose children still
            // have no buffers. It rewrites the whole template, so the top level is checked again too.
            if (AllocateNestedBuffers(template, allocatedBlocks, ref nestedMembers))
            {
                ReadAttributeValues(objectHandle, template);
                RestoreAndGuard(template, allocatedAt, allocatedLen);
                foreach (NestedMember member in nestedMembers!)
                    member.RestoreAndGuardSlot();
            }

            // Each array attribute ends up as one block its ObjectAttribute owns outright, and every
            // block not kept that way is freed (and zeroized) here rather than leaked.
            FoldAttributeArrays(template, allocatedBlocks, membersLaidOut: nestedMembers is not null);
        }
        catch
        {
            FreeAllocatedBlocks(allocatedBlocks);
            throw;
        }

        // Convert CK_ATTRIBUTEs to ObjectAttributes. Deliberately outside the try: from here the
        // ObjectAttributes own the blocks, and freeing them here too would be a double free.
        var outAttributes = new ObjectAttribute[template.Length];
        for (int i = 0; i < template.Length; i++)
            outAttributes[i] = new ObjectAttribute(template[i]);

        // The blocks belong to the caller from here; the returned list is what releases them. It
        // adopts the array rather than copying it: nothing else holds a reference to it.
        return ReadOnlyDisposableList<ObjectAttribute>.TakeOwnership(outAttributes);
    }

    /// <summary>
    /// Fills the type-only template the first <c>C_GetAttributeValue</c> call takes: it asks the
    /// module how long each value is, so the template carries no values and needs no buffers.
    /// </summary>
    /// <remarks>
    /// Built directly rather than through <c>ObjectAttribute</c>, which is <see cref="IDisposable"/>
    /// and was being constructed here only to have its struct copied out and the wrapper dropped.
    /// Adding a <see langword="using"/> would have been the wrong repair: the copy in the template shares the
    /// wrapper's pointer, so disposing would leave the template pointing at freed memory the moment a
    /// type-only attribute ever allocated one. Not creating the disposable avoids the question.
    /// </remarks>
    private static void BuildTypeOnlyTemplate(ReadOnlySpan<CKA> attributes, Span<CK_ATTRIBUTE> template)
    {
        for (int i = 0; i < attributes.Length; i++)
        {
            template[i] = new CK_ATTRIBUTE
            {
                type = attributes[i].ToCULong(),
                value = IntPtr.Zero,
                valueLen = (NativeCULong)0,
            };
        }
    }

    /// <summary>
    /// Issues one <c>C_GetAttributeValue</c> call over <paramref name="template"/> and throws on a
    /// return value that is fatal to the read — all three calls of the sequence go through here, so
    /// none of them can drift from the others on what counts as fatal.
    /// </summary>
    private void ReadAttributeValues(ObjectHandle objectHandle, Span<CK_ATTRIBUTE> template)
    {
        CKR rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template);
        if (IsGetAttributeValueFatal(rv))
            Pkcs11Exception.ThrowIfError(rv, OpGetAttributeValue);
    }

    /// <summary>
    /// Allocates a buffer for every attribute the module reported a length for, recording both the
    /// size allocated and the block, and leaves the unreadable ones alone.
    /// </summary>
    private static void AllocateValueBuffers(Span<CK_ATTRIBUTE> template, Span<IntPtr> allocatedAt, Span<NativeCULong> allocatedLen, List<IntPtr> allocatedBlocks)
    {
        for (int i = 0; i < template.Length; i++)
        {
            // PKCS#11 v2.20 page 133:
            // If the specified attribute (i.e., the attribute specified by the type field) for the object
            // cannot be revealed because the object is sensitive or unextractable, then the
            // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
            // CK_LONG, it holds -1).
            // Compare against the canonical sentinel (NativeCULong.MaxValue = uint.MaxValue on Windows,
            // ulong.MaxValue on Linux-LP64), as ObjectAttribute.CannotBeRead does. The previous
            // `.Value != nuint.MaxValue` only matched on Linux: on Win64 nuint is 8 bytes but CK_ULONG
            // is 4, so the -1 sentinel went unrecognized and (int)valueLen overflowed.
            if (template[i].valueLen == NativeCULong.MaxValue)
                continue;

            allocatedLen[i] = template[i].valueLen;
            allocatedAt[i] = UnmanagedMemory.Allocate((int)(template[i].valueLen));
            template[i].value = allocatedAt[i];
            allocatedBlocks.Add(allocatedAt[i]);
        }
    }

    /// <summary>
    /// Gives every nested attribute of every array attribute a buffer, and reports whether any were
    /// found — which is exactly the question of whether a third <c>C_GetAttributeValue</c> call is
    /// needed to fill them.
    /// </summary>
    private static bool AllocateNestedBuffers(
        Span<CK_ATTRIBUTE> template,
        List<IntPtr> allocatedBlocks,
        ref List<NestedMember>? nestedMembers)
    {
        bool thirdCallNeeded = false;

        for (int i = 0; i < template.Length; i++)
        {
            if (!AttributeArrayBlock.IsAttributeArray(template[i].type))
                continue;

            // PKCS#11 v2.20 page 133:
            // If the specified attribute (i.e., the attribute specified by the type field) for the object
            // cannot be revealed because the object is sensitive or unextractable, then the
            // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
            // CK_LONG, it holds -1).
            if (template[i].valueLen == NativeCULong.MaxValue)
                continue;

            thirdCallNeeded |= AllocateNestedChildBuffers(in template[i], allocatedBlocks, ref nestedMembers);
        }

        return thirdCallNeeded;
    }

    /// <summary>
    /// Allocates the child buffers of one array attribute, returning <see langword="false"/> when it
    /// declares no children.
    /// </summary>
    /// <exception cref="Pkcs11AttributeException">
    /// The reported length is not a whole number of <c>CK_ATTRIBUTE</c>s, so the module is not
    /// describing an attribute array at all.
    /// </exception>
    private static bool AllocateNestedChildBuffers(
        in CK_ATTRIBUTE parent,
        List<IntPtr> allocatedBlocks,
        ref List<NestedMember>? nestedMembers)
    {
        int ckAttributeSize = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();

        if ((int)(parent.valueLen) % ckAttributeSize != 0)
            throw new Pkcs11AttributeException((CKA)(ulong)parent.type);

        int nestedAttrCount = (int)(parent.valueLen) / ckAttributeSize;
        if (nestedAttrCount == 0)
            return false;

        for (int j = 0; j < nestedAttrCount; j++)
        {
            IntPtr tempPointer = new(parent.value.ToInt64() + (j * ckAttributeSize));
            CK_ATTRIBUTE tempAttribute = UnmanagedMemory.Read<CK_ATTRIBUTE>(tempPointer);

            // Recorded even when unreadable (no buffer): the module must not hand one back either.
            IntPtr buffer = IntPtr.Zero;
            NativeCULong allocated = default;
            if (tempAttribute.valueLen != NativeCULong.MaxValue)
            {
                allocated = tempAttribute.valueLen;
                buffer = UnmanagedMemory.Allocate((int)allocated);
                allocatedBlocks.Add(buffer);
            }
            (nestedMembers ??= []).Add(new NestedMember(tempPointer, buffer, allocated));

            tempAttribute.value = buffer;
            UnmanagedMemory.Write(tempPointer, in tempAttribute);
        }

        return true;
    }

    /// <summary>
    /// Resets every attribute's <c>pValue</c> to the buffer this session gave it, then checks the
    /// reported length against that buffer's size.
    /// </summary>
    /// <remarks>
    /// The module writes into the template (directly on Unix, through the packed copy on Windows), so
    /// it could hand back a different pointer. Restoring ours means the buffers read and freed later
    /// are always the ones this session allocated, never an address the module chose.
    /// </remarks>
    private static void RestoreAndGuard(Span<CK_ATTRIBUTE> template, ReadOnlySpan<IntPtr> allocatedAt, ReadOnlySpan<NativeCULong> allocatedLen)
    {
        for (int i = 0; i < template.Length; i++)
        {
            template[i].value = allocatedAt[i];
            GuardReportedLength(in template[i], allocatedLen[i]);
        }
    }

    /// <summary>One member of an array attribute, as this session laid it out for the third call.</summary>
    /// <param name="Slot">Where the member's <c>CK_ATTRIBUTE</c> sits in its parent's block.</param>
    /// <param name="Buffer">The buffer given to the member, or <see cref="IntPtr.Zero"/> when unreadable.</param>
    /// <param name="Allocated">The buffer's size.</param>
    private readonly record struct NestedMember(IntPtr Slot, IntPtr Buffer, NativeCULong Allocated)
    {
        /// <summary>
        /// The nested counterpart of the template-level <see cref="RestoreAndGuard"/>, applied to the
        /// member's <c>CK_ATTRIBUTE</c> at <see cref="Slot"/>.
        /// </summary>
        public void RestoreAndGuardSlot()
        {
            CK_ATTRIBUTE member = UnmanagedMemory.Read<CK_ATTRIBUTE>(Slot);
            member.value = Buffer;
            GuardReportedLength(in member, Allocated);
            UnmanagedMemory.Write(Slot, in member);
        }
    }

    /// <summary>
    /// Replaces each array attribute's parent and member buffers with one block laid out by
    /// <see cref="AttributeArrayBlock"/>, then frees every allocated block that no attribute keeps.
    /// </summary>
    /// <remarks>
    /// The members' buffers were separate allocations nobody would own once the read returned: the
    /// <see cref="ObjectAttribute"/> owns only its own value, and the views
    /// <see cref="ObjectAttribute.GetValueAsAttributeArray"/> returns own nothing. Folding them into
    /// the parent's block gives every byte one owner. On success <paramref name="allocatedBlocks"/>
    /// is emptied: what is not freed here belongs to the attributes. When no member was ever laid out
    /// and nothing was folded, every block is still the one its attribute points at, so all of them are
    /// kept without checking. Members laid out for a parent the third call then reported unreadable are
    /// not folded, and must still be found and freed.
    /// </remarks>
    private static void FoldAttributeArrays(Span<CK_ATTRIBUTE> template, List<IntPtr> allocatedBlocks, bool membersLaidOut)
    {
        List<IntPtr>? created = null;
        try
        {
            for (int i = 0; i < template.Length; i++)
            {
                CK_ATTRIBUTE attribute = template[i];
                if (!AttributeArrayBlock.IsAttributeArray(attribute.type)
                    || attribute.value == IntPtr.Zero
                    || attribute.valueLen == NativeCULong.MaxValue
                    || (ulong)attribute.valueLen == 0)
                    continue;

                CK_ATTRIBUTE[] members = AttributeArrayBlock.ReadMembers(attribute.type, attribute.value, attribute.valueLen);
                IntPtr block = AttributeArrayBlock.Create(members, out NativeCULong arrayLength);
                (created ??= []).Add(block);
                template[i].value = block;
                template[i].valueLen = arrayLength;
            }
        }
        catch
        {
            if (created is not null)
                FreeAllocatedBlocks(created);
            throw;
        }

        if (created is null && !membersLaidOut)
        {
            allocatedBlocks.Clear();
            return;
        }

        var kept = new HashSet<IntPtr>(template.Length);
        foreach (CK_ATTRIBUTE attribute in template)
            kept.Add(attribute.value);
        Span<IntPtr> blocks = CollectionsMarshal.AsSpan(allocatedBlocks);
        for (int i = 0; i < blocks.Length; i++)
        {
            if (!kept.Contains(blocks[i]))
                UnmanagedMemory.Free(ref blocks[i]);
        }
        allocatedBlocks.Clear();
    }

    /// <summary>Releases every block allocated for a read that then failed.</summary>
    /// <remarks>
    /// Freed through a span so that <c>Free</c>'s write-back lands in the list. <c>Free</c> nulls the
    /// pointer it is given and returns early on a null one — that pair is its double-free guard, and
    /// handing it a copy of each entry threw the guard away while looking like it was using it.
    /// </remarks>
    private static void FreeAllocatedBlocks(List<IntPtr> allocatedBlocks)
    {
        Span<IntPtr> blocks = CollectionsMarshal.AsSpan(allocatedBlocks);
        for (int i = 0; i < blocks.Length; i++)
            UnmanagedMemory.Free(ref blocks[i]);
    }

    /// <summary>
    /// Rejects a post-call <c>ulValueLen</c> larger than the buffer that was allocated to hold it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two-call idiom sizes each buffer from the length the module reports on the first call and
    /// hands it back on the second. Nothing obliges the module to report the same length twice, and
    /// every reader on <c>ObjectAttribute</c> sizes its read from whatever came back last — so a module
    /// that inflates the length, by bug or by design, walks those reads off the end of the allocation
    /// and returns whatever unmanaged memory follows it to the caller.
    /// </para>
    /// <para>
    /// The write direction is already covered: the buffer is the module's to fill, and the checked
    /// <c>NativeCULong</c> conversions catch a length that overflows outright. This is the
    /// in-range-but-oversized case, which nothing else catches and which fails silently.
    /// </para>
    /// </remarks>
    private static void GuardReportedLength(in CK_ATTRIBUTE attribute, NativeCULong allocated)
    {
        // The -1 sentinel means sensitive or unextractable; no buffer was allocated and none is read.
        if (attribute.valueLen == NativeCULong.MaxValue)
            return;

        if (attribute.valueLen <= allocated)
            return;

        throw new Pkcs11AttributeException((CKA)(ulong)attribute.type,
            $"The PKCS#11 module reported attribute 0x{(ulong)attribute.type:X} as "
            + $"{(ulong)attribute.valueLen} bytes after being given a {(ulong)allocated}-byte buffer "
            + "sized from its own earlier answer. Reading the value at the reported length would read "
            + "past the allocation, so it was refused.");
    }

    /// <summary>
    /// Modifies the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be modified</param>
    /// <param name="attributes">List of attributes that should be modified</param>
    public void SetAttributeValue(ObjectHandle objectHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetAttributeValue");


        ArgumentNullException.ThrowIfNull(attributes);

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = attributes[i].CkAttribute;

        CKR rv = _pkcs11Library.C_SetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template);
        Pkcs11Exception.ThrowIfError(rv, OpSetAttributeValue);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    public void FindObjectsInit(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjectsInit");

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsInit);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="objectCount">Maximum number of object handles to be returned</param>
    /// <returns>Found object handles</returns>
    public List<ObjectHandle> FindObjects(int objectCount)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjects");

        List<ObjectHandle> foundObjects = [];

        NativeCULong[] objects = new NativeCULong[objectCount];
        CKR rv = _pkcs11Library.C_FindObjects(_sessionId, objects, out NativeCULong foundObjectsCount);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjects);

        int found = ReportedLength.Written(foundObjectsCount, objects.Length, OpFindObjects);
        for (int i = 0; i < found; i++)
            foundObjects.Add(new ObjectHandle((ulong)objects[i]));

        return foundObjects;
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    public void FindObjectsFinal()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjectsFinal");

        CKR rv = _pkcs11Library.C_FindObjectsFinal(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsFinal);
    }

    /// <summary>
    /// Searches for all token and session objects that match provided attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    /// <returns>Handles of found objects</returns>
    public List<ObjectHandle> FindAllObjects(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindAllObjects");

        List<ObjectHandle> foundObjects = [];

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsInit);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

        try
        {
            Span<NativeCULong> objects = stackalloc NativeCULong[256];
            int found;
            do
            {
                rv = _pkcs11Library.C_FindObjects(_sessionId, objects, out NativeCULong objectCount);
                Pkcs11Exception.ThrowIfError(rv, OpFindObjects);

                found = ReportedLength.Written(objectCount, objects.Length, OpFindObjects);
                for (int i = 0; i < found; i++)
                    foundObjects.Add(new ObjectHandle((ulong)objects[i]));
            }
            while (found == objects.Length);
        }
        finally
        {
            // Best-effort finalize. Always runs so a mid-search exception cannot leave the
            // session wedged in "find active" state — the next C_FindObjectsInit would
            // otherwise fail with CKR_OPERATION_ACTIVE. Tolerate the rv: on the exception
            // unwind path we must not mask the original exception, and the session may
            // already be in a state where finalize fails harmlessly.
            CKR finalRv = _pkcs11Library.C_FindObjectsFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                Log.FindObjectsFinalFailed(_logger, (ulong)_sessionId, finalRv);
        }

        return foundObjects;
    }

    /// <summary>
    /// Returns <see langword="true"/> when a <c>C_GetAttributeValue</c> return value should
    /// terminate the read with an exception. The PKCS#11 spec defines
    /// <c>CKR_ATTRIBUTE_SENSITIVE</c> ("the attribute exists but cannot be read") and
    /// <c>CKR_ATTRIBUTE_TYPE_INVALID</c> ("the attribute does not apply to this object")
    /// as non-fatal indicators that should be reported back to the caller via the
    /// attribute's value-length sentinel rather than thrown.
    /// </summary>
    private static bool IsGetAttributeValueFatal(CKR rv)
        => rv is not CKR.CKR_OK
        and not CKR.CKR_ATTRIBUTE_SENSITIVE
        and not CKR.CKR_ATTRIBUTE_TYPE_INVALID;
}
