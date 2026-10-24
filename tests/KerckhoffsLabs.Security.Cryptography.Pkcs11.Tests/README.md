# Test layout

Tests are split into three top-level areas by **dependency**, which is also the rule for deciding
where a new test goes:

| Folder | What goes here | Backend |
|--------|----------------|---------|
| `Unit/` | Tests of a single type's contract — pure logic or driven by a `FakeModule`. | none (hermetic) |
| `Integration/` | Tests that exercise a real operation over **SoftHSM** or **pkcs11-mock**. | SoftHSM / mock |
| `Support/` | Shared test infrastructure (not tests themselves). | — |

## Where to put / find a test

- **Does it touch a token (SoftHSM or pkcs11-mock)?**
  - **No** → `Unit/`, mirroring the source path: `src/Native/UnmanagedMemory.cs` → `Unit/Native/UnmanagedMemoryTests.cs`. Root-namespace source types are grouped by area: `Unit/Info/` for `SlotInfo`/`TokenInfo`/…/`*Flags`/`SlotId`/`SessionId`, `Unit/Curves/` for the EC curve types; the rest (`SecurePin`, `Pkcs11Slot`, …) live directly under `Unit/`. Tests that enforce rules over the whole library (layer dependencies, public surface, naming and test conventions) live in `Unit/Architecture/`.
  - **Yes** → `Integration/<operation>`: `Sign/`, `Verify/`, `Encrypt/`, `Decrypt/`, `Digest/`, `Derive/`, `Keys/`, `Auth/`, `Discovery/`, `Lifecycle/`, `Objects/`, `Random/`, `Security/`, `ThreadSafety/`, `Smoke/`. The BCL adapter end-to-end tests (`RSAPkcs11Tests`, … and `KnownAnswerTests`) are in `Integration/Adapters/`.

Namespaces follow folders (`…Tests.Unit.Native`, `…Tests.Integration.Sign`), which enables fast
filtering:

```bash
# hermetic unit tests only — no SoftHSM build needed, ~0.5s
dotnet test -- --filter-query "/*/*.Tests.Unit*/*/*"

# backend integration tests only
dotnet test -- --filter-query "/*/*.Tests.Integration*/*/*"
```

## Conventions & exceptions

- **`Support/`** holds `Fixtures/` (SoftHSM + mock backends, xUnit collection definitions),
  `Fakes/` (`Modules/`: `FakeModule`, managed PKCS#11 modules loaded through the real loader;
  `SoftToken/`: `ManagedSoftToken`, an in-process token that performs real crypto), and the ambient helpers `TestKeys`, `Settings`, and
  `CapturingLogger`. The ambient helpers intentionally keep the **assembly-root namespace**
  (`…Tests`) so any test can use them without an extra `using`.
- **`Integration/MemoryLeaks/`** is kept as one group even though some of its tests are hermetic:
  they share a single serialized xUnit collection (the process-wide `UnmanagedMemory` allocation
  tracker must not see concurrent allocations during a leak snapshot), and that cohesion outranks the
  unit/integration split.
- A type can legitimately appear in both areas — e.g. `Pkcs11SessionCore` has fake-driven unit tests
  *and* SoftHSM behavioral tests. That's expected: they're different kinds of test.

## Parallelization and backend collections

The assembly runs **one collection per class, collections in parallel** — stated explicitly in
`Support/TestParallelization.cs` rather than left to the xUnit defaults. A class that declares no
`[Collection]` therefore runs concurrently with everything else, which is right for the hermetic
`Unit/` tests and wrong for anything touching a backend: pkcs11-mock is single-session and
process-global, and each of the SoftHSM / NSS / opencryptoki fixtures owns one `C_Initialize`'d
module.

So **every test class under `Integration/` must declare one of two things**:

| Declaration | When |
|-------------|------|
| `[Collection("Mock" \| "SoftHsm" \| "Nss" \| "OpenCryptoki" \| "Kryoptic" \| "BouncyHsm" \| "CratonHsm" \| "Tpm2Pkcs11" \| "MemoryLeaks")]` | It drives that backend — the collection serializes its tests and owns the module lifetime. |
| `[NoBackendCollection("why")]` | It touches no process-global native state (in-process `ManagedSoftToken`, or a static `File.Exists` availability probe). |

`Unit/Architecture/TestCollectionConventionTests` enforces this, so a forgotten `[Collection]` fails
deterministically at the moment the class is added instead of surfacing later as an intermittent
native-state corruption. It also checks, across the whole assembly (`Algorithms/` included), that a
class named `*_Mock` / `*_SoftHsm` / `*_Nss` / `*_OpenCryptoki` / `*_Kryoptic` / `*_BouncyHsm` / `*_CratonHsm` / `*_Tpm2Pkcs11` joins the matching collection, that
an injected collection fixture is actually supplied by the declared collection, and that no
`[Collection]` names a definition that doesn't exist.

Note that a collection **serializes its members**, so don't park unrelated classes in one to satisfy
the rule — `[NoBackendCollection]` exists precisely so parallel-safe classes stay parallel.

## Running against BouncyHsm locally

BouncyHsm is built from `vendor/bouncyhsm` by an opt-in target (a cold build publishes the server,
about 3 minutes):

```bash
git submodule update --init vendor/bouncyhsm
dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:BuildBouncyHsm=true
```

You don't start anything yourself. `BouncyHsmBackendFixture` starts a private, in-memory server on
random loopback ports, creates its token, and kills the server when the run ends. A test host that is
killed hard can leave that server behind. It holds nothing on disk and doesn't affect the next run,
but you may want to end it (`pkill -f 'bouncyhsm/server/BouncyHsm.dll'`, which matches only the copy the
build staged next to the test assembly).

The BouncyHsm backend is supported on Linux x64 only, and CI runs it on ubuntu-latest, like the other
extra backends. On any other platform the build target does nothing and the BouncyHsm tests skip.
Known BouncyHsm bugs are gated on `BouncyHsmBackendFixture` (see `BouncyHsmQuirkTests`).
