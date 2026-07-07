#include <common.h>
#include <crypto.h>
#include <base64.h>

using namespace stardust;

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   32
#define SHA256_SIZE    32

auto declfn starburst::crypto_init(
    _Inout_ instance& inst
) -> bool {
    NTSTATUS status;

    DBG_PRINT( inst, "crypto_init: BCryptOpenAlgorithmProvider=%p\n", inst.bcrypt_mod.BCryptOpenAlgorithmProvider );
    DBG_PRINT( inst, "crypto_init: bcrypt_mod.handle=%p\n", (void*)inst.bcrypt_mod.handle );

    if ( !inst.bcrypt_mod.BCryptOpenAlgorithmProvider ) {
        DBG_PRINT( inst, "crypto_init: BCryptOpenAlgorithmProvider is NULL!\n" );
        return false;
    }

    status = inst.bcrypt_mod.BCryptOpenAlgorithmProvider(
        &inst.crypto.h_aes,
        symbol<LPCWSTR>( L"AES" ),
        nullptr,
        0
    );
    DBG_PRINT( inst, "crypto_init: AES provider status=0x%08X\n", status );
    if ( status != 0 ) return false;

    status = inst.bcrypt_mod.BCryptSetProperty(
        inst.crypto.h_aes,
        symbol<LPCWSTR>( L"ChainingMode" ),
        reinterpret_cast<PUCHAR>( symbol<LPWSTR>( const_cast<wchar_t*>( L"ChainingModeCBC" ) ) ),
        sizeof(L"ChainingModeCBC"),
        0
    );
    DBG_PRINT( inst, "crypto_init: SetProperty status=0x%08X\n", status );
    if ( status != 0 ) return false;

    status = inst.bcrypt_mod.BCryptOpenAlgorithmProvider(
        &inst.crypto.h_sha256,
        symbol<LPCWSTR>( L"SHA256" ),
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    DBG_PRINT( inst, "crypto_init: SHA256 provider status=0x%08X\n", status );
    if ( status != 0 ) return false;

    DBG_PRINT( inst, "crypto_init: success\n" );
    return true;
}

auto declfn starburst::crypto_encrypt(
    _Inout_ instance& inst,
    _In_    uint8_t*  key,
    _In_    uint8_t*  plaintext,
    _In_    uint32_t  plain_len,
    _Out_   uint8_t** out,
    _Out_   uint32_t* out_len
) -> bool {
    BCRYPT_KEY_HANDLE h_key = nullptr;
    NTSTATUS status;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t iv_copy[AES_BLOCK_SIZE];

    status = inst.bcrypt_mod.BCryptGenRandom( nullptr, iv, AES_BLOCK_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    if ( status != 0 ) return false;

    memory::copy( iv_copy, iv, AES_BLOCK_SIZE );

    status = inst.bcrypt_mod.BCryptGenerateSymmetricKey(
        inst.crypto.h_aes, &h_key, nullptr, 0,
        key, AES_KEY_SIZE, 0
    );
    if ( status != 0 ) return false;

    uint32_t padded_len = ((plain_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

    auto padded = static_cast<uint8_t*>( inst.heap_alloc( padded_len ) );
    if ( !padded ) { inst.bcrypt_mod.BCryptDestroyKey( h_key ); return false; }

    memory::copy( padded, plaintext, plain_len );
    uint8_t pad_val = padded_len - plain_len;
    for ( uint32_t i = plain_len; i < padded_len; i++ ) {
        padded[i] = pad_val;
    }

    ULONG cipher_len = 0;
    status = inst.bcrypt_mod.BCryptEncrypt(
        h_key, padded, padded_len,
        nullptr, iv_copy, AES_BLOCK_SIZE,
        nullptr, 0, &cipher_len, 0
    );
    if ( status != 0 ) {
        inst.heap_free( padded );
        inst.bcrypt_mod.BCryptDestroyKey( h_key );
        return false;
    }

    auto cipher = static_cast<uint8_t*>( inst.heap_alloc( cipher_len ) );
    if ( !cipher ) {
        inst.heap_free( padded );
        inst.bcrypt_mod.BCryptDestroyKey( h_key );
        return false;
    }

    memory::copy( iv_copy, iv, AES_BLOCK_SIZE );

    status = inst.bcrypt_mod.BCryptEncrypt(
        h_key, padded, padded_len,
        nullptr, iv_copy, AES_BLOCK_SIZE,
        cipher, cipher_len, &cipher_len, 0
    );

    inst.heap_free( padded );
    inst.bcrypt_mod.BCryptDestroyKey( h_key );

    if ( status != 0 ) {
        inst.heap_free( cipher );
        return false;
    }

    // HMAC-SHA256 over IV + ciphertext
    BCRYPT_HASH_HANDLE h_hmac = nullptr;
    status = inst.bcrypt_mod.BCryptCreateHash(
        inst.crypto.h_sha256, &h_hmac,
        nullptr, 0, key, AES_KEY_SIZE, 0
    );
    if ( status != 0 ) {
        inst.heap_free( cipher );
        return false;
    }

    inst.bcrypt_mod.BCryptHashData( h_hmac, iv, AES_BLOCK_SIZE, 0 );
    inst.bcrypt_mod.BCryptHashData( h_hmac, cipher, cipher_len, 0 );

    uint8_t hmac[SHA256_SIZE];
    inst.bcrypt_mod.BCryptFinishHash( h_hmac, hmac, SHA256_SIZE, 0 );
    inst.bcrypt_mod.BCryptDestroyHash( h_hmac );

    // output = IV (16) + ciphertext + HMAC (32)
    uint32_t total_len = AES_BLOCK_SIZE + cipher_len + SHA256_SIZE;
    auto output = static_cast<uint8_t*>( inst.heap_alloc( total_len ) );
    if ( !output ) {
        inst.heap_free( cipher );
        return false;
    }

    memory::copy( output, iv, AES_BLOCK_SIZE );
    memory::copy( output + AES_BLOCK_SIZE, cipher, cipher_len );
    memory::copy( output + AES_BLOCK_SIZE + cipher_len, hmac, SHA256_SIZE );

    inst.heap_free( cipher );

    *out     = output;
    *out_len = total_len;

    return true;
}

auto declfn starburst::crypto_decrypt(
    _Inout_ instance& inst,
    _In_    uint8_t*  key,
    _In_    uint8_t*  cipherblob,
    _In_    uint32_t  blob_len,
    _Out_   uint8_t** out,
    _Out_   uint32_t* out_len
) -> bool {
    if ( blob_len < AES_BLOCK_SIZE + SHA256_SIZE + AES_BLOCK_SIZE ) return false;

    uint8_t* iv_ptr     = cipherblob;
    uint32_t cipher_len = blob_len - AES_BLOCK_SIZE - SHA256_SIZE;
    uint8_t* cipher_ptr = cipherblob + AES_BLOCK_SIZE;
    uint8_t* hmac_ptr   = cipherblob + AES_BLOCK_SIZE + cipher_len;

    // verify HMAC
    BCRYPT_HASH_HANDLE h_hmac = nullptr;
    NTSTATUS status = inst.bcrypt_mod.BCryptCreateHash(
        inst.crypto.h_sha256, &h_hmac,
        nullptr, 0, key, AES_KEY_SIZE, 0
    );
    if ( status != 0 ) return false;

    inst.bcrypt_mod.BCryptHashData( h_hmac, iv_ptr, AES_BLOCK_SIZE, 0 );
    inst.bcrypt_mod.BCryptHashData( h_hmac, cipher_ptr, cipher_len, 0 );

    uint8_t computed_hmac[SHA256_SIZE];
    inst.bcrypt_mod.BCryptFinishHash( h_hmac, computed_hmac, SHA256_SIZE, 0 );
    inst.bcrypt_mod.BCryptDestroyHash( h_hmac );

    if ( memory::compare( computed_hmac, hmac_ptr, SHA256_SIZE ) != 0 ) return false;

    // decrypt
    uint8_t iv_copy[AES_BLOCK_SIZE];
    memory::copy( iv_copy, iv_ptr, AES_BLOCK_SIZE );

    BCRYPT_KEY_HANDLE h_key = nullptr;
    status = inst.bcrypt_mod.BCryptGenerateSymmetricKey(
        inst.crypto.h_aes, &h_key, nullptr, 0,
        key, AES_KEY_SIZE, 0
    );
    if ( status != 0 ) return false;

    ULONG plain_len = 0;
    status = inst.bcrypt_mod.BCryptDecrypt(
        h_key, cipher_ptr, cipher_len,
        nullptr, iv_copy, AES_BLOCK_SIZE,
        nullptr, 0, &plain_len, 0
    );
    if ( status != 0 ) {
        inst.bcrypt_mod.BCryptDestroyKey( h_key );
        return false;
    }

    auto plain = static_cast<uint8_t*>( inst.heap_alloc( plain_len ) );
    if ( !plain ) {
        inst.bcrypt_mod.BCryptDestroyKey( h_key );
        return false;
    }

    memory::copy( iv_copy, iv_ptr, AES_BLOCK_SIZE );

    status = inst.bcrypt_mod.BCryptDecrypt(
        h_key, cipher_ptr, cipher_len,
        nullptr, iv_copy, AES_BLOCK_SIZE,
        plain, plain_len, &plain_len, 0
    );

    inst.bcrypt_mod.BCryptDestroyKey( h_key );

    if ( status != 0 ) {
        inst.heap_free( plain );
        return false;
    }

    // strip PKCS7 padding
    uint8_t pad_val = plain[plain_len - 1];
    if ( pad_val > 0 && pad_val <= AES_BLOCK_SIZE ) {
        plain_len -= pad_val;
    }

    *out     = plain;
    *out_len = plain_len;

    return true;
}

auto declfn starburst::crypto_destroy(
    _Inout_ instance& inst
) -> void {
    if ( inst.crypto.h_aes ) {
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider( inst.crypto.h_aes, 0 );
        inst.crypto.h_aes = nullptr;
    }
    if ( inst.crypto.h_sha256 ) {
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider( inst.crypto.h_sha256, 0 );
        inst.crypto.h_sha256 = nullptr;
    }
}
