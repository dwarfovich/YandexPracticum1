#include "crypto_guard_ctx.h"

#include <openssl/evp.h>

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

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *const>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
};

void CryptoGuardCtx::Impl::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    if (!inStream) {
        throw std::runtime_error{"Input stream is not valid"};
    }
    if (!outStream) {
        throw std::runtime_error{"Output stream is not valid"};
    }

    using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype([](auto *ptr) { EVP_CIPHER_CTX_free(ptr); })>;
    CipherContext cipherContext_{EVP_CIPHER_CTX_new()};
    const auto &cipherParameters_ = CreateCipherParamsFromPassword(password, CipherOperation::ENCRYPT);

    std::vector<unsigned char> inBuffer(cipherParameters_.BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(cipherParameters_.BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

    /* Don't set key or IV right away; we want to check lengths */
    if (!EVP_CipherInit_ex2(cipherContext_.get(), cipherParameters_.cipher, nullptr, nullptr,
                            cipherParameters_.operation == CipherOperation::DECRYPT ? 0 : 1, nullptr)) {
        throw std::runtime_error{"Failed to initialize cipher"};
    }
    if (EVP_CIPHER_CTX_get_key_length(cipherContext_.get()) != cipherParameters_.KEY_SIZE) {
        throw std::runtime_error{"Unexpected key length"};
    }
    if (EVP_CIPHER_CTX_get_iv_length(cipherContext_.get()) != cipherParameters_.IV_SIZE) {
        throw std::runtime_error{"Unexpected IV length"};
    }

    if (!EVP_CipherInit_ex2(cipherContext_.get(), nullptr, cipherParameters_.key.data(), cipherParameters_.iv.data(),
                            cipherParameters_.operation == CipherOperation::DECRYPT ? 0 : 1, nullptr)) {
        throw std::runtime_error{"Failed to set key and IV"};
    }

    int outLength = 0;
    while (true) {
        inStream.read(reinterpret_cast<char * const>(inBuffer.data()), inBuffer.size());
        if (!inStream && !inStream.eof()) {
            throw std::runtime_error{"Failed to read data from inStream"};
        }
        const auto bytesRead = inStream.gcount();
        if (!EVP_CipherUpdate(cipherContext_.get(), outBuffer.data(), &outLength, inBuffer.data(), bytesRead)) {
            throw std::runtime_error{"Failed to update cipher"};
        }
        outStream.write(reinterpret_cast<const char * const>(outBuffer.data()), bytesRead);
        if (!outStream) {
            throw std::runtime_error("Write failed");
        }
        if (bytesRead < inBuffer.size()) {
            break;
        }
    }
    if (!EVP_CipherFinal_ex(cipherContext_.get(), outBuffer.data(), &outLength)) {
        throw std::runtime_error{"Failed to finalize encryption"};
    }
    outStream.write(reinterpret_cast<const char * const>(outBuffer.data()), outLength);
    if (!outStream) {
        throw std::runtime_error("Write failed");
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_{std::make_unique<Impl>()} {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
