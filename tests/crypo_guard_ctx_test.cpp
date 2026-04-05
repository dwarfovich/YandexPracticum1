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

TEST(TestCryptoGuardCtx, TestEncryptDecrypt) {
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