//
// Created by Ian Buss on 02/04/2016.
//

#ifndef ENCRYPTUTILS_ENCRYPTUTILS_H
#define ENCRYPTUTILS_ENCRYPTUTILS_H

#include <string>
#include <vector>
#include <base64.h>
#include <osrng.h>
#include <cryptlib.h>
#include <hex.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>

using CryptoPP::AES;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::CFB_Mode;
using CryptoPP::ArraySink;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
using byte_vec = std::vector<unsigned char>;

const int KEY_LENGTH = 32;
const int IV_LENGTH = 16;
const int AES_BLOCK_LENGTH = 16;

struct Key {
  unsigned char material[KEY_LENGTH];
};

struct IV {
  unsigned char material[IV_LENGTH];
};

class EncryptUtils {
public:
  EncryptUtils();

  byte_vec* encrypt(const byte_vec& plaintext, const Key& key, const IV& iv);
  std::string encrypt(const std::string& plaintext, const Key& key, const IV& iv);

  byte_vec* decrypt(const byte_vec& ciphertext, const Key& key, const IV& iv);
  std::string decrypt(const std::string& ciphertext, const Key& key, const IV& iv);

  Key* generate_key();
  IV* generate_iv();

  ~EncryptUtils() {}
private:
  AutoSeededRandomPool prng;
};

#endif //ENCRYPTUTILS_ENCRYPTUTILS_H
