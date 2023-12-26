#include "php.h"
#include "php_mocrypt.h"
#include <openssl/aes.h>
#include <openssl/rand.h>

ZEND_FUNCTION(mo_encrypt)
{
    char *content_to_encrypt;
    char *secret_key;
    size_t content_to_encrypt_len, secret_key_len;
    zval result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &content_to_encrypt, &content_to_encrypt_len, &secret_key, &secret_key_len) == FAILURE)
    {
        RETURN_NULL();
    }

    AES_KEY aes_key;
    char *iv = emalloc(AES_BLOCK_SIZE);
    char *key = emalloc(32);

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, (unsigned char *)secret_key, secret_key_len, 1, (unsigned char *)key, (unsigned char *)iv);

    int pad_len = AES_BLOCK_SIZE - (content_to_encrypt_len % AES_BLOCK_SIZE);
    char *padded_content = emalloc(content_to_encrypt_len + pad_len + 1);
    memcpy(padded_content, content_to_encrypt, content_to_encrypt_len);
    memset(padded_content + content_to_encrypt_len, pad_len, pad_len);

    AES_set_encrypt_key((unsigned char *)key, 256, &aes_key);
    AES_cbc_encrypt((unsigned char *)padded_content, (unsigned char *)padded_content, content_to_encrypt_len + pad_len, &aes_key, (unsigned char *)iv, AES_ENCRYPT);

    efree(iv);
    efree(key);

    ZVAL_STRING(&result, base64_encode((unsigned char *)padded_content, content_to_encrypt_len + pad_len));
    efree(padded_content);

    RETURN_ZVAL(&result, 0, 1);
}

ZEND_FUNCTION(mo_decrypt)
{
    char *content_to_decrypt;
    char *secret_key;
    size_t content_to_decrypt_len, secret_key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &content_to_decrypt, &content_to_decrypt_len, &secret_key, &secret_key_len) == FAILURE)
    {
        RETURN_NULL();
    }

    AES_KEY aes_key;
    char *iv = emalloc(AES_BLOCK_SIZE);
    char *key = emalloc(32);

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, (unsigned char *)secret_key, secret_key_len, 1, (unsigned char *)key, (unsigned char *)iv);

    AES_set_decrypt_key((unsigned char *)key, 256, &aes_key);
    AES_cbc_encrypt((unsigned char *)base64_decode((unsigned char *)content_to_decrypt, content_to_decrypt_len), (unsigned char *)content_to_decrypt, content_to_decrypt_len, &aes_key, (unsigned char *)iv, AES_DECRYPT);

    efree(iv);
    efree(key);

    zend_eval_string(content_to_decrypt, NULL, "Decrypted Code" TSRMLS_CC);

    RETURN_LONG(0);
}

ZEND_BEGIN_ARG_INFO(arginfo_mo_encrypt, 0)
    ZEND_ARG_INFO(0, content_to_encrypt)
    ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_mo_decrypt, 0)
    ZEND_ARG_INFO(0, content_to_decrypt)
    ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

const zend_function_entry mocrypt_functions[] = {
    ZEND_FE(mo_encrypt, arginfo_mo_encrypt)
    ZEND_FE(mo_decrypt, arginfo_mo_decrypt)
    ZEND_FE_END
};

zend_module_entry mocrypt_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "mocrypt",
    mocrypt_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    "1.0",
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MOCRYPT
ZEND_GET_MODULE(mocrypt)
#endif
