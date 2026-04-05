#include "crypto_guard_ctx.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace CryptoGuard {

enum class CipherOperation {
    DECRYPT = 0,
    ENCRYPT = 1,
};

void ThrowOpenSslErrorException(const std::string &exceptionMessage, unsigned long openSslErrorCode,
                                const std::string &context) {
    static const std::size_t errorMessageBufferSize = 256;
    char errorBuffer[errorMessageBufferSize];
    ERR_error_string(openSslErrorCode, errorBuffer);
    throw std::runtime_error{exceptionMessage + ", OpenSSL error code: " + std::to_string(openSslErrorCode) + " (" +
                             errorBuffer + "); Context: " + context};
}

struct AesCipherParams {
    AesCipherParams(CipherOperation op) : operation(op) {}

    static const std::size_t KEY_SIZE = 32;  // AES-256 key size
    static const std::size_t IV_SIZE = 16;   // AES block size (IV length)
    static const std::size_t BUFFER_SIZE = 1024;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    CipherOperation operation;
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateCipherParamsFromPassword(std::string_view password, CipherOperation operation) {
    AesCipherParams params{operation};
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};
    const int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                      reinterpret_cast<const unsigned char *const>(password.data()), password.size(), 1,
                                      params.key.data(), params.iv.data());
    if (!result) {
        ThrowOpenSslErrorException("Failed to create a key from password", ERR_get_error(), "Create cipher params");
    }

    return params;
}

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    void PerformCipherOperation(std::istream &inStream, std::ostream &outStream, std::string_view password,
                                CipherOperation operation);
};

void CryptoGuardCtx::Impl::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    PerformCipherOperation(inStream, outStream, password, CipherOperation::ENCRYPT);
}

void CryptoGuardCtx::Impl::PerformCipherOperation(std::istream &inStream, std::ostream &outStream,
                                                  std::string_view password, CipherOperation operation) {
    if (!inStream) {
        throw std::runtime_error{"Input stream is not valid"};
    }
    if (!outStream) {
        throw std::runtime_error{"Output stream is not valid"};
    }

    using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype([](auto *ptr) { EVP_CIPHER_CTX_free(ptr); })>;
    CipherContext cipherContext{EVP_CIPHER_CTX_new()};
    const auto &cipherParameters = CreateCipherParamsFromPassword(password, operation);
    const auto operationCode = (operation == CipherOperation::DECRYPT ? 0 : 1);

    std::vector<unsigned char> inBuffer(cipherParameters.BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(cipherParameters.BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

    /* Checking key and IV lengths */
    if (!EVP_CipherInit_ex2(cipherContext.get(), cipherParameters.cipher, nullptr, nullptr, operationCode, nullptr)) {
        throw std::runtime_error{"Failed to initialize cipher"};
    }
    if (EVP_CIPHER_CTX_get_key_length(cipherContext.get()) != cipherParameters.KEY_SIZE) {
        throw std::runtime_error{"Unexpected key length"};
    }
    if (EVP_CIPHER_CTX_get_iv_length(cipherContext.get()) != cipherParameters.IV_SIZE) {
        throw std::runtime_error{"Unexpected IV length"};
    }

    if (!EVP_CipherInit_ex2(cipherContext.get(), nullptr, cipherParameters.key.data(), cipherParameters.iv.data(),
                            operationCode, nullptr)) {
        ThrowOpenSslErrorException("Failed to set key or IV", ERR_get_error(), "Initialize cipher with key and IV");
    }

    int outLength = 0;
    std::size_t bytesRead = 0;
    do{
        inStream.read(reinterpret_cast<char *const>(inBuffer.data()), inBuffer.size());
        if (!inStream && !inStream.eof()) {
            throw std::runtime_error{"Failed to read data from inStream"};
        }
        bytesRead = inStream.gcount();
        if (!EVP_CipherUpdate(cipherContext.get(), outBuffer.data(), &outLength, inBuffer.data(), bytesRead)) {
            ThrowOpenSslErrorException("Failed to update cipher", ERR_get_error(), "Cipher update");
        }
        outStream.write(reinterpret_cast<const char *const>(outBuffer.data()), outLength);
        if (!outStream) {
            throw std::runtime_error("Write failed");
        }
    } while (bytesRead >= inBuffer.size());

    if (!EVP_CipherFinal_ex(cipherContext.get(), outBuffer.data(), &outLength)) {
        ThrowOpenSslErrorException("Failed to finalize encryption", ERR_get_error(), "Finalizing cipher");
    }
    outStream.write(reinterpret_cast<const char *const>(outBuffer.data()), outLength);
    if (!outStream) {
        throw std::runtime_error("Write failed");
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    PerformCipherOperation(inStream, outStream, password, CipherOperation::DECRYPT);
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_{std::make_unique<Impl>()} {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
