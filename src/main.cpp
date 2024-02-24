#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <iostream>

using namespace CryptoPP;
int main(int argc, char *argv[]) {


  std::cout << "key length: " << AES::DEFAULT_KEYLENGTH << std::endl;
  std::cout << "key length (min): " << AES::MIN_KEYLENGTH << std::endl;
  std::cout << "key length (max): " << AES::MAX_KEYLENGTH << std::endl;
  std:: cout << "block size: " << AES::BLOCKSIZE << '\n';
  return 0;
}
