#include "gcm.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cassert>
#include <iostream>
int main(int argc, char *argv[]) {
  CryptoPP::AutoSeededRandomPool prng;

  // Key
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  // iv vector
  CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  const int TAG_SIZE{12};

  // plain text
  std::string pdata{"MY PLAIN TEXT"};

  // Encrypted cipher with tage
  std::string cipher;
  // binary to hex
  std::string encoded;

  // recovered plain text
  std::string rpdata;
  // Pretty print
  encoded.clear();
  CryptoPP::StringSource keyPrint(
      key, sizeof(key), true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)) // HexEncoder
  ); // StringSource
  std::cout << "key: " << encoded << '\n';

  // Pretty print
  encoded.clear();
  CryptoPP::StringSource ivPrint(
      iv, sizeof(iv), true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)) // HexEncoder
  ); // StringSource
  std::cout << " iv: " << encoded << '\n';

  std::cout << '\n';

  // Encryption process
  try {
    std::cout << "Plain Text: " << pdata << '\n';
    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    CryptoPP::StringSource(pdata, true,
                           new CryptoPP::AuthenticatedEncryptionFilter(
                               e, new CryptoPP::StringSink(cipher), false,
                               TAG_SIZE) // AuthenticatedEncryptionFilter
    );                                   // StringSource
  } catch (CryptoPP::InvalidArgument &e) {

    std::cerr << "Caught InvalidArgument..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::Exception &e) {

    std::cerr << "Caught Exception..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  }
  // TIll this section It prints the Plain text and Encrypts it.

  // Now we print cipher text
  // Pretty print
  encoded.clear();
  CryptoPP::StringSource(
      cipher, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)) // HexEncoder
  ); // StringSource
  std::cout << "cipher text: " << encoded << std::endl;

  try {
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    CryptoPP::AuthenticatedDecryptionFilter df(
        decryption, new CryptoPP::StringSink(rpdata),
        CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
        TAG_SIZE); // AuthenticatedDecryptionFilter

    CryptoPP::StringSource(
        cipher, true,
        new CryptoPP::Redirector(df /*, PASS_EVERYTHING */)); // StringSource

    bool b = df.GetLastResult();
    assert(true == b);

    std::cout << "recovered text: " << rpdata << std::endl;
  } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e) {
    std::cerr << "Caught HashVerificationFailed..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::InvalidArgument &e) {
    std::cerr << "Caught InvalidArgument..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::Exception &e) {
    std::cerr << "Caught Exception..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  }
return 0;
}
