#ifndef PHP_MOCRYPT_H
#define PHP_MOCRYPT_H 1

#define PHP_MOCRYPT_VERSION "1.0"
#define PHP_MOCRYPT_EXTNAME "mocrypt"

PHP_FUNCTION(mo_encrypt);
PHP_FUNCTION(mo_decrypt);

extern zend_module_entry mocrypt_module_entry;
#define phpext_mocrypt_ptr &mocrypt_module_entry

#endif
