# Test layout

Tests are split into three top-level areas by **dependency**, which is also the rule for deciding
where a new test goes:

| Folder | What goes here | Backend |
|--------|----------------|---------|
| `Unit/` | Tests of a single type's contract — pure logic or driven by `FakeLowLevelPkcs11Library`. | none (hermetic) |
| `Integration/` | Tests that exercise a real operation over **SoftHSM** or **pkcs11-mock**. | SoftHSM / mock |
| `Support/` | Shared test infrastructure (not tests themselves). | — |

## Where to put / find a test

- **Does it touch a token (SoftHSM or pkcs11-mock)?**
  - **No** → `Unit/`, mirroring the source path: `src/Native/UnmanagedMemory.cs` → `Unit/Native/UnmanagedMemoryTests.cs`. Root-namespace source types (the BCL adapters' *value* types, `SlotInfo`/`TokenInfo`/…/`*Flags`, `SecurePin`, `Pkcs11Slot`) live directly under `Unit/`.
  - **Yes** → `Integration/<operation>`: `Sign/`, `Verify/`, `Encrypt/`, `Decrypt/`, `Digest/`, `Derive/`, `Keys/`, `Auth/`, `Discovery/`, `Lifecycle/`, `Objects/`, `Random/`, `Security/`, `ThreadSafety/`, `Smoke/`. The BCL adapter end-to-end tests (`RSAPkcs11Tests`, … and `KnownAnswerTests`) are in `Integration/Adapters/`.

Namespaces follow folders (`…Tests.Unit.Native`, `…Tests.Integration.Sign`), which enables fast
filtering:

```bash
# hermetic unit tests only — no SoftHSM build needed, ~0.5s
dotnet test --filter "FullyQualifiedName~.Tests.Unit."

# backend integration tests only
dotnet test --filter "FullyQualifiedName~.Tests.Integration."
```

## Conventions & exceptions

- **`Support/`** holds `Fixtures/` (SoftHSM + mock backends, xUnit collection definitions),
  `Fakes/` (`FakeLowLevelPkcs11Library`), and the ambient helpers `TestKeys`, `Settings`, and
  `CapturingLogger`. The ambient helpers intentionally keep the **assembly-root namespace**
  (`…Tests`) so any test can use them without an extra `using`.
- **`Integration/MemoryLeaks/`** is kept as one group even though some of its tests are hermetic:
  they share a single serialized xUnit collection (the `UnmanagedMemory.DebugModeEnabled` /
  allocation-tracker static state must not be toggled concurrently), and that cohesion outranks the
  unit/integration split.
- A type can legitimately appear in both areas — e.g. `Pkcs11Session` has fake-driven unit tests
  *and* SoftHSM behavioral tests. That's expected: they're different kinds of test.
