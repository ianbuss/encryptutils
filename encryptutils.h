//
// Created by Ian Buss on 02/04/2016.
//

#ifndef ENCRYPTUTILS_ENCRYPTUTILS_H
#define ENCRYPTUTILS_ENCRYPTUTILS_H

#include <string>
#include <vector>
#include <openssl/evp.h>

const int KEY_LENGTH = 32;
const int IV_LENGTH = 16;
const int AES_BLOCK_LENGTH = 16;

using binary_vec = std::vector<unsigned char>;

struct Key {
  unsigned char material[KEY_LENGTH];
};

struct IV {
  unsigned char material[IV_LENGTH];
};

class EncryptUtils {
public:
  EncryptUtils();

  binary_vec* encrypt(const char* plaintext, const Key& key, const IV& iv);
  std::string encrypt(const std::string& plaintext, const Key& key, const IV& iv);

  binary_vec* decrypt(const binary_vec& ciphertext, const Key& key, const IV& iv);
  std::string decrypt(const std::string& ciphertext, const Key& key, const IV& iv);

  Key* generate_key();
  IV* generate_iv();

  ~EncryptUtils() {}
private:
  void handle_error(EVP_CIPHER_CTX* ctx);
  int ciphertext_len(int plaintext_len);

  static std::string base64_encode(const binary_vec& buffer);
  static binary_vec* base64_decode(const std::string& b64_string);
  static unsigned long base64_decode_len(const std::string& b64_string);
};

#endif //ENCRYPTUTILS_ENCRYPTUTILS_H
