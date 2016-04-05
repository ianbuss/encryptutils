//
// Created by Ian Buss on 05/04/2016.
//

#include <iostream>
#include "encryptutils.h"

int main(int argc, const char* argv[]) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " STRING_TO_ENCRYPT" << std::endl;
    return 1;
  }

  std::string to_encrypt { argv[1] };

  EncryptUtils encrypter;

  Key* key = encrypter.generate_key();
  IV* iv = encrypter.generate_iv();

  std::cout << "Input: " << to_encrypt << std::endl;
  std::string encrypted = encrypter.encrypt(to_encrypt, *key, *iv);
  std::cout << "Encrypted: " << encrypted << std::endl;
  std::string decrypted = encrypter.decrypt(encrypted, *key, *iv);
  std::cout << "Decrypted: " << decrypted << std::endl;
}