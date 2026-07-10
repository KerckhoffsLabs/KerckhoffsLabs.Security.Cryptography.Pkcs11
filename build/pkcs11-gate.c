/*
 * pkcs11-gate: a PKCS#11 "spec-version gate" for compatibility testing.
 *
 * Wraps a real PKCS#11 module (path read from the environment variable named by
 * GATE_TARGET_ENV) and restricts the API version a consumer can negotiate, so the
 * test suite can validate the wrapper's behavior against module spec-version tiers
 * that no CI backend represents natively:
 *
 *   default build ("gate 2.40"):
 *     Exports ONLY C_GetFunctionList, forwarding to the target. No C_GetInterface,
 *     no per-symbol v3.x exports — to a loader this is exactly a v2.40-only module,
 *     while the function table still points at the target's real implementations.
 *
 *   -DGATE_EXPOSE_V30 ("gate 3.0"):
 *     Additionally exports C_GetInterface, which returns a private copy of the
 *     target's default interface whose function list is truncated to
 *     CK_FUNCTION_LIST_3_0 and whose version header is rewritten to {3, 0} — a
 *     faithful v3.0-but-not-v3.2 module regardless of what the target implements.
 *
 * The target is dlopen'ed with RTLD_LOCAL. Tests point the env var at a private
 * file COPY of the real module so the gate gets its own independent instance
 * (its own C_Initialize state) even when the original is already loaded in-process.
 */
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11.h" /* vendor/softhsmv2/src/lib/pkcs11 (p11-kit style, self-contained) */

#ifndef GATE_TARGET_ENV
#error "GATE_TARGET_ENV must name the environment variable holding the target module path"
#endif

static void *gate_target(void)
{
    static void *handle;
    if (!handle) {
        const char *path = getenv(GATE_TARGET_ENV);
        if (path)
            handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    }
    return handle;
}

static void *gate_sym(const char *name)
{
    void *h = gate_target();
    return h ? dlsym(h, name) : NULL;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pp_function_list)
{
    CK_RV (*real)(CK_FUNCTION_LIST_PTR_PTR) =
        (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))gate_sym("C_GetFunctionList");
    if (!real)
        return CKR_GENERAL_ERROR;
    return real(pp_function_list);
}

#ifdef GATE_EXPOSE_V30

static CK_FUNCTION_LIST_3_0 gate_fl30;
static CK_INTERFACE gate_iface;
static char gate_iface_name[] = "PKCS 11";

CK_RV C_GetInterface(CK_UTF8CHAR_PTR interface_name, CK_VERSION_PTR version,
                     CK_INTERFACE_PTR_PTR pp_interface, CK_FLAGS flags)
{
    CK_RV (*real)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) =
        (CK_RV (*)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS))
            gate_sym("C_GetInterface");
    if (!real)
        return CKR_FUNCTION_NOT_SUPPORTED;
    if (!pp_interface)
        return CKR_ARGUMENTS_BAD;

    /* The gate always filters the target's default interface. */
    (void)interface_name;
    (void)version;

    CK_INTERFACE_PTR iface = NULL;
    CK_RV rv = real(NULL, NULL, &iface, flags);
    if (rv != CKR_OK)
        return rv;
    if (!iface || !iface->pFunctionList)
        return CKR_GENERAL_ERROR;

    /* Truncating to CK_FUNCTION_LIST_3_0 is only meaningful over a 3.x table. */
    if (((CK_VERSION *)iface->pFunctionList)->major < 3)
        return CKR_GENERAL_ERROR;

    memcpy(&gate_fl30, iface->pFunctionList, sizeof gate_fl30);
    gate_fl30.version.major = 3;
    gate_fl30.version.minor = 0;

    gate_iface.pInterfaceName = gate_iface_name;
    gate_iface.pFunctionList = &gate_fl30;
    gate_iface.flags = iface->flags;

    *pp_interface = &gate_iface;
    return CKR_OK;
}

#endif /* GATE_EXPOSE_V30 */
