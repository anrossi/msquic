/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Custom TLS implementation for MsQuic

Environment:

    Windows user mode

--*/

#include "platform_internal.h"

typedef enum HANDSHAKE_TYPE {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
} HANDSHAKE_TYPE;

typedef struct CXPLAT_TLS {

    struct {
        uint8_t IsServer : 1;
    };

} CXPLAT_TLS;


BOOLEAN
ReadUint24(
    _In_reads_bytes_(BufferLength - *Offset) uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ uint16_t* Offset,
    _Out_ uint32_t* Value
    )
{
    if (Buffer == NULL) {
        return FALSE;
    }
    if (*Offset + 3 > BufferLength) {
        return FALSE;
    }
    *Value = ((uint32_t)Buffer[*Offset] << 16) | ((uint32_t)Buffer[*Offset + 1] << 8) | Buffer[*Offset + 2];
    *Offset += 3;
    return TRUE;
}

BOOLEAN
WriteUint24(
    _In_ uint32_t Value,
    _In_ uint16_t BufferLength,
    _Inout_ uint16_t* Offset,
    _Out_writes_bytes_(BufferLength - *Offset) uint8_t* Buffer
    )
{
    if (Value > 0xfffffful) {
        return FALSE;
    }
    if (*Offset + 3 > BufferLength) {
        return FALSE;
    }
    Buffer[*Offset] = (uint8_t)((Value >> 16) & 0xff);
    Buffer[*Offset + 1] = (uint8_t)((Value >> 8) & 0xff);
    Buffer[*Offset + 2] = (uint8_t)(Value & 0xff);
    *Offset += 3;
    return TRUE;
}

BOOLEAN
IsHandshakeTypeSupported(
    _In_ HANDSHAKE_TYPE Input
    )
{
    switch(Input) {
    case client_hello:
    case server_hello:
    case new_session_ticket:
    case encrypted_extensions:
    case certificate:
    case certificate_request:
    case certificate_verify:
    case finished:
        return TRUE;
    default:
        return FALSE;
    }
}

QUIC_STATUS
CxPlatTlsLibraryInitialize(
    void
    )
{
    // TODO
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
CxPlatTlsLibraryUninitialize(
    void
    )
{
    // TODO
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status;
    CXPLAT_TLS* TlsContext = CXPLAT_ALLOC_NONPAGED(sizeof(*TlsContext), QUIC_POOL_TLS_CTX);  
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    TlsContext->IsServer = Config->IsServer;

    // TODO

    *NewTlsContext = TlsContext;
    TlsContext = NULL;
    Status = QUIC_STATUS_SUCCESS;

Error:
    if (TlsContext != NULL) {
        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

QUIC_STATUS
WriteClientHello(
    _In_ CXPLAT_TLS* TlsContext,
    _Inout_ uint16_t* BufferLength,
    _Out_writes_bytes_(*BufferLength)
        uint8_t* Buffer
    )
{
    QUIC_STATUS Status;
    //
    // Calculate the size needed before writing anything
    //
    uint16_t RequiredLength =
        1 +     // HandshakeType
        3 +     // Length
        2 +     // ProtocolVersion
        32 +    // Random
        1 +     // legacy_session_id
        2 +     // cipher_suites (just one for now)
        1 +     // legacy_compression_methods
        2 +     // supported_versions extension ExtensionType
        2;      // TLS1.3 supported_version

    uint16_t HelloLength = 42; // TODO this will need to be calculated, as well as the above

    if (*BufferLength < RequiredLength) {
        *BufferLength = RequiredLength;
        Status = QUIC_STATUS_BUFFER_TOO_SMALL;
        goto Error;
    }
    if (Buffer == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    uint16_t Index = 0;
    Buffer[Index] = (uint8_t)client_hello;
    Index++;

    if (WriteUint24(HelloLength, *BufferLength, &Index, Buffer)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Buffer[Index] = 0x03;   // ProtocolVersion
    Index++;
    Buffer[Index] = 0x03;   // ProtocolVersion
    Index++;
    CxPlatRandom(32, Buffer + Index);
    Index += 32;
    Buffer[Index] = 0;      // legacy_session_id
    Index++;
    Buffer[Index] = 0x13;   // Cipher suite (TLS_AES_128_GCM_SHA256)
    Index++;
    Buffer[Index] = 0x01;   // Cipher suite (TLS_AES_128_GCM_SHA256)
    Index++;
    Buffer[Index] = 0;      // legacy_compression_methods
    Index++;
    Buffer[Index] = 0;      // ExtensionType
    Index++;
    Buffer[Index] = 43;     // ExtensionType
    Index++;
    Buffer[Index] = 0x03;   // TLS1.3 supported_version
    Index++;
    Buffer[Index] = 0x04;   // TLS1.3 supported_version
    Index++;


    *BufferLength = RequiredLength;
    Status = QUIC_STATUS_SUCCESS;
Error:
    return Status;
}
