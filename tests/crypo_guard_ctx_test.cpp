#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

TEST(TestCryptoGuardCtx, TestEncrypt_ClosedStreams) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::ifstream ifStream;
    ifStream.close();
    std::ostringstream outStringStream;
    ASSERT_THROW(cryptoCtx.EncryptFile(ifStream, outStringStream, "1"), std::runtime_error);

    std::ofstream ofStream;
    ofStream.close();
    std::istringstream inStringStream;
    ASSERT_THROW(cryptoCtx.EncryptFile(inStringStream, ofStream, "1"), std::runtime_error);
}

TEST(TestCryptoGuardCtx, TestEncrypt_BadBitInStreams) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStream;
    inStream.setstate(std::ios::badbit);
    std::ostringstream outStream;
    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1"), std::runtime_error);

    inStream.setstate(std::ios::goodbit);
    outStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1"), std::runtime_error);
}

TEST(TestCryptoGuardCtx, TestEncrypt_EmptyInput) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream in;
    std::ostringstream out;

    cryptoCtx.EncryptFile(in, out, "pass");

    ASSERT_FALSE(out.str().empty());  // padding должен быть
}

TEST(TestCryptoGuardCtx, TestEncrypt_SanityCheck1Byte) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream in{'a'};
    std::ostringstream out;

    cryptoCtx.EncryptFile(in, out, "pass");

    ASSERT_GT(out.str().size(), in.str().size());
}

TEST(TestCryptoGuardCtx, TestEncrypt_SanityCheck1023Byte) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::string inStr(1023, 'a');
    std::istringstream in{inStr};
    std::ostringstream out;

    cryptoCtx.EncryptFile(in, out, "pass");

    ASSERT_GT(out.str().size(), in.str().size());
}

TEST(TestCryptoGuardCtx, TestEncrypt_SanityCheck1024Byte) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::string inStr(1024, 'a');
    std::istringstream in{inStr};
    std::ostringstream out;

    cryptoCtx.EncryptFile(in, out, "pass");

    ASSERT_GT(out.str().size(), in.str().size());
}

TEST(TestCryptoGuardCtx, TestEncryptDecrypt_EmptyInput) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        std::istringstream in{""};
        std::stringstream encrypted;
        cryptoCtx.EncryptFile(in, encrypted, "pass");
        std::ostringstream decryptedOut;
        cryptoCtx.DecryptFile(encrypted, decryptedOut, "pass");

        ASSERT_EQ(in.str(), decryptedOut.str());
    } catch (const std::exception &ex) {
        FAIL() << "Exception thrown during Encrypt/Decrypt: " << ex.what();
    }
}

TEST(TestCryptoGuardCtx, TestEncryptDecrypt_SmallInput) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        std::istringstream in{"1"};
        std::stringstream encrypted;
        cryptoCtx.EncryptFile(in, encrypted, "pass");
        std::ostringstream decryptedOut;
        cryptoCtx.DecryptFile(encrypted, decryptedOut, "pass");

        ASSERT_EQ(in.str(), decryptedOut.str());
    } catch (const std::exception &ex) {
        FAIL() << "Exception thrown during Encrypt/Decrypt: " << ex.what();
    }
}

TEST(TestCryptoGuardCtx, TestEncryptDecrypt_BufferSizedInput) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        std::istringstream in{std::string(1024, 'a')};
        std::stringstream encrypted;
        cryptoCtx.EncryptFile(in, encrypted, "pass");
        std::ostringstream decryptedOut;
        cryptoCtx.DecryptFile(encrypted, decryptedOut, "pass");

        ASSERT_EQ(in.str(), decryptedOut.str());
    } catch (const std::exception &ex) {
        FAIL() << "Exception thrown during Encrypt/Decrypt: " << ex.what();
    }
}

TEST(TestCryptoGuardCtx, TestEncryptDecrypt_GreaterThanBufferInput) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        std::istringstream in{std::string(1500, 'a')};
        std::stringstream encrypted;
        cryptoCtx.EncryptFile(in, encrypted, "pass");
        std::ostringstream decryptedOut;
        cryptoCtx.DecryptFile(encrypted, decryptedOut, "pass");

        ASSERT_EQ(in.str(), decryptedOut.str());
    } catch (const std::exception &ex) {
        FAIL() << "Exception thrown during Encrypt/Decrypt: " << ex.what();
    }
}

TEST(TestCryptoGuardCtx, TestEncryptDecrypt_IncorrectDecryptPassword) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::istringstream in{"Hello, OpenSSL!"};
    std::stringstream encrypted;
    cryptoCtx.EncryptFile(in, encrypted, "pass");
    std::ostringstream decryptedOut;
    ASSERT_THROW(cryptoCtx.DecryptFile(encrypted, decryptedOut, "wrong_pass"), std::runtime_error);
}

TEST(TestCryptoGuardCtx, TestHash_EmptyString) {
    std::istringstream inStream{""};
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_EQ(cryptoCtx.CalculateChecksum(inStream),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(TestCryptoGuardCtx, TestHash_SingleCharInput) {
    std::istringstream inStream{"1"};
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_EQ(cryptoCtx.CalculateChecksum(inStream),
              "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b");
}

TEST(TestCryptoGuardCtx, TestHash_SanityCheck) {
    std::istringstream inStream{"Hello"};
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_EQ(cryptoCtx.CalculateChecksum(inStream),
              "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969");
}

TEST(TestCryptoGuardCtx, TestHash_InputGreaterThanBuffer) {
    std::istringstream inStream{std::string(4500, 'a')};
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_EQ(cryptoCtx.CalculateChecksum(inStream),
              "73c3e7c56fc1cef8692b4a750b2572b16c74aad07095faef124529104eeb44eb");
}

std::pair<std::string, std::string> CalculateHashesWithEncyptionDecryption(const std::string& input){
    std::istringstream inStream{input};
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    auto originalHash = cryptoCtx.CalculateChecksum(inStream);
    inStream.clear();
    inStream.seekg(0);
    std::stringstream encryptedStream;
    cryptoCtx.EncryptFile(inStream, encryptedStream, "Password");
    std::stringstream decryptedStream;
    cryptoCtx.DecryptFile(encryptedStream, decryptedStream, "Password");
    auto decryptedHash = cryptoCtx.CalculateChecksum(decryptedStream);
    
    return {std::move(originalHash), std::move(decryptedHash)};
}

TEST(TestCryptoGuardCtx, TestHashAfterEncryptionDecryption_EmptyInput) {
    const auto &hashes = CalculateHashesWithEncyptionDecryption("");
    ASSERT_EQ(hashes.first, hashes.second);
}

TEST(TestCryptoGuardCtx, TestHashAfterEncryptionDecryption_SingleChar) {
    const auto &hashes = CalculateHashesWithEncyptionDecryption("1");
    ASSERT_EQ(hashes.first, hashes.second);
}

TEST(TestCryptoGuardCtx, TestHashAfterEncryptionDecryption_SanityCheck) {
    const auto &hashes = CalculateHashesWithEncyptionDecryption("Hello, world!");
    ASSERT_EQ(hashes.first, hashes.second);
}