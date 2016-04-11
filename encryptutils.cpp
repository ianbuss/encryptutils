//
// Created by Ian Buss on 02/04/2016.
//

#include <iostream>
#include <stdexcept>

#include "encryptutils.h"


EncryptUtils::EncryptUtils() { }

byte_vec* EncryptUtils::encrypt(const byte_vec& plaintext, const Key& key, const IV& iv) {
  try {
    CFB_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key.material, KEY_LENGTH, iv.material);

    // CFB mode must not use padding. Specifying
    //  a scheme will result in an exception
    byte_vec* ciphertext = new std::vector<unsigned char>(plaintext.size());
    ArraySink* arraysink = new ArraySink(ciphertext->data(), ciphertext->size());
    StreamTransformationFilter* transformer = new StreamTransformationFilter(e, arraysink);

    StringSource(plaintext.data(),
                 plaintext.size(),
                 true,
                 transformer);
    return ciphertext;
  }
  catch(const CryptoPP::Exception& e)
  {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error { "Error encrypting" };
  }
}

std::string EncryptUtils::encrypt(const std::string& plaintext, const Key& key, const IV& iv) {
  try {
    CFB_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key.material, KEY_LENGTH, iv.material);

    // CFB mode must not use padding. Specifying
    //  a scheme will result in an exception
    std::string ciphertext;
    StringSink* stringsink = new StringSink(ciphertext);
    Base64Encoder* b64encoder = new Base64Encoder(stringsink, false);
    StreamTransformationFilter* transformer = new StreamTransformationFilter(e, b64encoder);

    StringSource(plaintext,
                 true,
                 transformer);
    return ciphertext;
  }
  catch(const CryptoPP::Exception& e)
  {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error { "Error encrypting" };
  }
}

byte_vec* EncryptUtils::decrypt(const byte_vec& ciphertext, const Key& key, const IV& iv) {
  try
  {
    CFB_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key.material, KEY_LENGTH, iv.material);

    // The StreamTransformationFilter removes
    //  padding as required.
    byte_vec* plaintext = new std::vector<unsigned char>(ciphertext.size());
    ArraySink* stringsink = new ArraySink(plaintext->data(), plaintext->size());
    Base64Decoder* b64decoder = new Base64Decoder(stringsink);
    StreamTransformationFilter* transformer = new StreamTransformationFilter(d, b64decoder);

    StringSource(ciphertext.data(), ciphertext.size(), true, transformer);

    return plaintext;
  }
  catch(const CryptoPP::Exception& e)
  {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error { "Error decrypting" };
  }
}

std::string EncryptUtils::decrypt(const std::string& ciphertext, const Key& key, const IV& iv) {
  try
  {
    CFB_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key.material, KEY_LENGTH, iv.material);

    std::string plaintext, decoded;
    StringSource(ciphertext, true,
                 new Base64Decoder(
                     new StringSink(decoded)
                 )
    );
    StringSink* stringsink = new StringSink(plaintext);
    StreamTransformationFilter* transformer = new StreamTransformationFilter(d, stringsink);

    StringSource(decoded, true, transformer);

    return plaintext;
  }
  catch(const CryptoPP::Exception& e)
  {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error { "Error decrypting" };
  }
}

Key* EncryptUtils::generate_key() {
  Key* key = new Key;
  prng.GenerateBlock(key->material, KEY_LENGTH);
  return key;
}

IV* EncryptUtils::generate_iv() {
  IV* iv = new IV;
  prng.GenerateBlock(iv->material, IV_LENGTH);
  return iv;
}
