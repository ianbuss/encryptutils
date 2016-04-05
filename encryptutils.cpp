//
// Created by Ian Buss on 02/04/2016.
//

#include <openssl/buffer.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdexcept>

#include "encryptutils.h"


EncryptUtils::EncryptUtils() {
  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

binary_vec* EncryptUtils::encrypt(const char* plaintext, const Key& key, const IV& iv) {
  EVP_CIPHER_CTX *ctx;
  int len, plen, clen;

  // Create and initialise the context
  if(!(ctx = EVP_CIPHER_CTX_new())) handle_error(ctx);
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.material, iv.material))
    handle_error(ctx);

  // Encrypt the plaintext
  plen = static_cast<int>(strlen(plaintext));
  clen = ciphertext_len(plen);
  binary_vec* ciphertext = new std::vector<unsigned char>(clen);
  if(1 != EVP_EncryptUpdate(ctx, ciphertext->data(), &len, reinterpret_cast<const unsigned char*>(plaintext), plen))
    handle_error(ctx);
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext->data() + len, &len))
    handle_error(ctx);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext;
}

std::string EncryptUtils::encrypt(const std::string& plaintext, const Key& key, const IV& iv) {
  binary_vec* ciphertext = encrypt(plaintext.c_str(), key, iv);
  return base64_encode(*ciphertext);
}

binary_vec* EncryptUtils::decrypt(const binary_vec& ciphertext, const Key& key, const IV& iv) {
  EVP_CIPHER_CTX *ctx;
  int len;
  unsigned long clen;

  // Create and initialise the context
  if(!(ctx = EVP_CIPHER_CTX_new())) handle_error(ctx);
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.material, iv.material))
    handle_error(ctx);

  // Decrypt the ciphertext
  clen = ciphertext.size();
  binary_vec* plaintext = new std::vector<unsigned char>(clen);
  if(1 != EVP_DecryptUpdate(ctx, plaintext->data(), &len, reinterpret_cast<unsigned char*>(plaintext), clen))
    handle_error(ctx);
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext->data() + len, &len)) handle_error(ctx);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return plaintext;
}

std::string EncryptUtils::decrypt(const std::string& ciphertext, const Key& key, const IV& iv) {
  binary_vec* ciphertext_raw = base64_decode(ciphertext);
  binary_vec* plaintext_raw = decrypt(*ciphertext_raw, key, iv);
  return std::string { reinterpret_cast<char*>(plaintext_raw) };
}

Key* EncryptUtils::generate_key() {
  Key* key = new Key;
  if(!RAND_bytes(key->material, sizeof(key->material))) {
    throw std::runtime_error {"Could not generate random key"};
  }
  return key;
}

IV* EncryptUtils::generate_iv() {
  IV* iv = new IV;
  if(!RAND_bytes(iv->material, sizeof(iv->material))) {
    throw std::runtime_error {"Could not generate random IV"};
  }
  return iv;
}

void EncryptUtils::handle_error(EVP_CIPHER_CTX* ctx) {
  unsigned long err = ERR_get_error();
  char error_string[256];
  ERR_error_string_n(err, error_string, 256);
  if (ctx != nullptr)
    EVP_CIPHER_CTX_free(ctx);
  throw std::runtime_error { error_string };
}

int EncryptUtils::ciphertext_len(int plaintext_len) {
  int num_blocks = plaintext_len / AES_BLOCK_LENGTH;
  return std::max(AES_BLOCK_LENGTH, num_blocks);
}

std::string EncryptUtils::base64_encode(const binary_vec& buffer) { //Encodes a binary safe base 64 string
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(bio, buffer.data(), static_cast<int>(buffer.size()));
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  return std::string { bufferPtr->data };
}

binary_vec* EncryptUtils::base64_decode(const std::string& b64_string) { //Decodes a base64 encoded string
  BIO *bio, *b64;

  unsigned long decode_len = base64_decode_len(b64_string);
  binary_vec* buffer = new std::vector<unsigned char>(decode_len);

  const char* b64_cstring = b64_string.c_str();
  bio = BIO_new_mem_buf(const_cast<char*>(b64_cstring), -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  BIO_read(bio, buffer->data(), static_cast<int>(b64_string.size()));
  BIO_free_all(bio);

  return buffer; //success
}

unsigned long EncryptUtils::base64_decode_len(const std::string& b64_string) {
  int padding = 0;
  unsigned long len = b64_string.size();

  if (b64_string[len-1] == '=' && b64_string[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64_string[len-1] == '=') //last char is =
    padding = 1;

  return (len*3)/4 - padding;
}