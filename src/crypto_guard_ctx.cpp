#include "crypto_guard_ctx.h"
#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>

#pragma region CryptoGuard
namespace CryptoGuard {
#pragma region details
namespace details {
struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0)
        throw std::runtime_error{"Failed to create a key from password"};

    return params;
}
std::string GetErrorInfo() {
    std::string res;
    unsigned long errCode = ERR_get_error();
    if (errCode != 0) {
        res = std::string(256, '\0');
        ERR_error_string_n(errCode, res.data(), res.size());
        res.resize(std::strlen(res.c_str()));
    }
    return res;
}

size_t StreamCounter(std::istream &in) {
    if (!in)
        return 0;

    auto originalPos = in.tellg();
    if (originalPos == -1) {
        throw std::runtime_error("Stream does not support seeking");
    }

    in.seekg(0, std::ios::end);
    size_t count = in.tellg();
    in.seekg(originalPos);
    return count;
}
std::string BytesToHexString(const std::vector<std::byte> &data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::byte b : data)
        oss << std::setw(2) << static_cast<int>(std::to_integer<unsigned char>(b));
    return oss.str();
}
}  // end namespace details
#pragma endregion
//////////////////////////////////////////////////////////////////////////////////
#pragma region CryptoGuardCtx::Impl
constexpr size_t IN_BUF_SIZE = 1024;
constexpr size_t OUT_BUF_SIZE = IN_BUF_SIZE + EVP_MAX_BLOCK_LENGTH;
constexpr size_t BUF_SIZE = 1024;

class CryptoGuardCtx::Impl {
public:
    Impl(Impl &&) = default;
    Impl &operator=(Impl &&) = default;
    ~Impl() = default;

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    Impl(std::istream &in, std::string_view password, Action iAction) : Impl() {
        auto params = details::CreateChiperParamsFromPassword(password);
        switch (iAction) {
        case Action::Encrypt:
            params.encrypt = 1;
            break;
        case Action::Decrypt:
            params.encrypt = 0;
            break;
        default:
            throw std::runtime_error("Wrong action");
        }

        CtxPtrED _ctx(EVP_CIPHER_CTX_new());
        if (!_ctx)
            throw std::runtime_error(std::format("Failed to create EVP context: {}", details::GetErrorInfo()));

        if (EVP_CipherInit_ex(_ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                              params.encrypt) != 1)
            throw std::runtime_error(std::format("EVP_CipherInit_ex: {}", details::GetErrorInfo()));

        if (EVP_CIPHER_CTX_set_padding(_ctx.get(), 1) != 1)
            throw std::runtime_error(std::format("EVP_CIPHER_CTX_set_padding: {}", details::GetErrorInfo()));

        std::array<std::byte, OUT_BUF_SIZE> outBuf;
        std::array<std::byte, IN_BUF_SIZE> inBuf;
        int outLen = 0;

        do {
            in.read(reinterpret_cast<char *>(inBuf.data()), IN_BUF_SIZE);
            if (std::streamsize readLen = in.gcount()) {
                if (EVP_CipherUpdate(_ctx.get(), reinterpret_cast<unsigned char *>(outBuf.data()), &outLen,
                                     reinterpret_cast<unsigned char *>(inBuf.data()), static_cast<int>(readLen)) != 1)
                    throw std::runtime_error(std::format("EVP_CipherUpdate failed: {}", details::GetErrorInfo()));

                _out.insert(_out.end(), outBuf.begin(), outBuf.begin() + outLen);
            }
        } while (in && !in.eof());
        if (in.bad())
            throw std::runtime_error("Stream read error");

        if (EVP_CipherFinal_ex(_ctx.get(), reinterpret_cast<unsigned char *>(outBuf.data()), &outLen) != 1)
            throw std::runtime_error(std::format("EVP_CipherFinal_ex failed: {}", details::GetErrorInfo()));

        _out.insert(_out.end(), outBuf.begin(), outBuf.begin() + outLen);
        _ready = true;
    }
    Impl(std::istream &in) : Impl() {
        std::array<std::byte, BUF_SIZE> buffer;
        std::array<std::byte, EVP_MAX_MD_SIZE> hash;
        unsigned int hashLen = 0;

        CtxPtrMD ctx(EVP_MD_CTX_new());
        if (!ctx)
            throw std::runtime_error("Failed to create EVP_MD_CTX");

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
            throw std::runtime_error(std::format("EVP_DigestInit_ex failed: {}", details::GetErrorInfo()));

        do {
            in.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
            if (std::streamsize readLen = in.gcount()) {
                if (EVP_DigestUpdate(ctx.get(), buffer.data(), readLen) != 1)
                    throw std::runtime_error(std::format("EVP_DigestUpdate failed: {}", details::GetErrorInfo()));
            }
        } while (in && !in.eof());
        if (in.bad())
            throw std::runtime_error("Stream read error");

        if (EVP_DigestFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(hash.data()), &hashLen) != 1)
            throw std::runtime_error(std::format("EVP_DigestFinal_ex failed: {}", details::GetErrorInfo()));

        _out.insert(_out.end(), hash.begin(), hash.begin() + hashLen);
        _ready = true;
    }

    bool IsReady() const noexcept { return _ready; }

    std::vector<std::byte> &&GetResult() noexcept {
        _ready = false;
        return std::move(_out);
    }

private:
    Impl() : _ready(false) {}

    using CtxPtrED = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); })>;
    using CtxPtrMD = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); })>;

    std::vector<std::byte> _out;
    bool _ready;
};
#pragma endregion
//////////////////////////////////////////////////////////////////////////////////
#pragma region CryptoGuardCtx
CryptoGuardCtx::CryptoGuardCtx() : pImpl_(nullptr) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EDProcess(std::istream &inStream, std::ostream &outStream, std::string_view password,
                               Action iAction) {
    if (!details::StreamCounter(inStream))
        throw std::runtime_error("Empty input");
    pImpl_ = std::make_unique<Impl>(inStream, password, iAction);
    if (pImpl_->IsReady()) {
        auto data = pImpl_->GetResult();
        if (!data.empty())
            outStream.write(reinterpret_cast<const char *>(data.data()), data.size());
    }
}

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    EDProcess(inStream, outStream, password, Action::Encrypt);
}
void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    EDProcess(inStream, outStream, password, Action::Decrypt);
}
std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) {
    std::string res;
    if (!details::StreamCounter(inStream))
        throw std::runtime_error("Empty input");
    pImpl_ = std::make_unique<Impl>(inStream);
    if (pImpl_->IsReady())
        res = details::BytesToHexString(pImpl_->GetResult());
    return res;
}
#pragma endregion
}  // namespace CryptoGuard
#pragma endregion
//////////////////////////////////////////////////////////////////////////////////
