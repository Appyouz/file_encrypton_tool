
#include "gcm.h"
#include <cassert>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <string>

void encrypt(const std::string& inputFile, const std::string& outputFile);
void decryptFile(const std::string& cipherFile, const std::string& outputFile);

int main() {
    std::string inputFile, outputFile;
    char choice;

    std::cout << "Enter input file path: ";
    std::cin >> inputFile;

    std::cout << "Enter output file path: ";
    std::cin >> outputFile;

    std::cout << "Choose an option:\n";
    std::cout << "1. Encrypt\n";
    std::cout << "2. Decrypt\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    switch (choice) {
        case '1':
            encrypt(inputFile, outputFile);
            break;
        case '2':
            decryptFile(inputFile, outputFile);
            break;
        default:
            std::cout << "Invalid choice.\n";
            break;
    }

    return 0;
}

void encrypt(const std::string& inputFile, const std::string& outputFile) {
    const int TAG_SIZE = 12;
    std::string plainText;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::cout << "Generated Key (Hex): ";
    CryptoPP::StringSource(key, key.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    std::cout << "Generated IV (Hex): ";
    CryptoPP::StringSource(iv, iv.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    try {
        // Read plaintext from file
        CryptoPP::FileSource file(inputFile.c_str(), true,
                                  new CryptoPP::StringSink(plainText));

        // Encryption process
        std::string cipher;
        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource(plainText, true,
                               new CryptoPP::AuthenticatedEncryptionFilter(
                                       e, new CryptoPP::StringSink(cipher), false, TAG_SIZE));

        // Write encrypted data to cipher file
        CryptoPP::FileSink fileSink(outputFile.c_str());
        fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(cipher.data()), cipher.size());

        std::cout << "Encryption successful." << std::endl;

        // Write key and IV to file
        try {
            std::ofstream keyIvFile("key_iv.txt");
            if (keyIvFile.is_open()) {
                keyIvFile << CryptoPP::HexEncoder(new CryptoPP::FileSink(keyIvFile)).Put(key, key.size());
                keyIvFile << std::endl;
                keyIvFile << CryptoPP::HexEncoder(new CryptoPP::FileSink(keyIvFile)).Put(iv, iv.size());
                keyIvFile.close();
                std::cout << "Key and IV written to key_iv.txt." << std::endl;
            } else {
                std::cerr << "Unable to open key_iv.txt for writing." << std::endl;
            }
        } catch (const std::exception& ex) {
            std::cerr << "Error writing key and IV to file: " << ex.what() << std::endl;
        }
    } catch (const CryptoPP::Exception &e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
    }
}

void decryptFile(const std::string& cipherFile, const std::string& outputFile) {
    std::ifstream keyIvFile("key_iv.txt");
    std::string keyHex, ivHex;
    std::getline(keyIvFile, keyHex);
    std::getline(keyIvFile, ivHex);
    keyIvFile.close();

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH), iv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::StringSource(keyHex, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(key, key.size())));
    CryptoPP::StringSource(ivHex, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(iv, iv.size())));
    const int TAG_SIZE = 12;

    // Print keys
    std::cout << "Key (Hex): ";
    CryptoPP::StringSource(key, key.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    std::cout << "IV (Hex): ";
    CryptoPP::StringSource(iv, iv.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    // Decryption
    try {
        std::string cipherText;
        CryptoPP::FileSource file(cipherFile.c_str(), true,
                                  new CryptoPP::StringSink(cipherText));

        std::string recoveredText;
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::AuthenticatedDecryptionFilter df(d, new CryptoPP::StringSink(recoveredText),
                                                    CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                                                    TAG_SIZE);

        CryptoPP::StringSource(cipherText, true, new CryptoPP::Redirector(df));
        if (!df.GetLastResult()) {
            std::cerr << "Decryption failed." << std::endl;
            return;
        }

        // Write decrypted data to file
        CryptoPP::FileSink fileSink(outputFile.c_str());
        fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(recoveredText.data()), recoveredText.size());

        std::cout << "Decryption successful. Recovered text: " << recoveredText << std::endl;
    } catch (const CryptoPP::Exception &e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
    }
}
