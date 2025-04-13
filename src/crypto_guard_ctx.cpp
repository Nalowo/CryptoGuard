#include "crypto_guard_ctx.h"
#include <openssl/evp.h>
#include <vector>
#include <array>
#include <iostream>

#pragma region CryptoGuard
namespace CryptoGuard
{
#pragma region details
    namespace details
    {
        struct AesCipherParams
        {
            static const size_t KEY_SIZE = 32;            // AES-256 key size
            static const size_t IV_SIZE = 16;             // AES block size (IV length)
            const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Cipher algorithm

            int encrypt;                             // 1 for encryption, 0 for decryption
            std::array<unsigned char, KEY_SIZE> key; // Encryption key
            std::array<unsigned char, IV_SIZE> iv;   // Initialization vector
        };

        AesCipherParams CreateChiperParamsFromPassword(std::string_view password)
        {
            AesCipherParams params;
            constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

            int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                        reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                        params.key.data(), params.iv.data());

            if (result == 0)
                throw std::runtime_error{"Failed to create a key from password"};

            return params;
        }
    } // end namespace details
#pragma endregion
//////////////////////////////////////////////////////////////////////////////////
#pragma region CryptoGuardCtx::Impl
    constexpr size_t IN_BUF_SIZE = 4096;
    constexpr size_t OUT_BUF_SIZE = IN_BUF_SIZE + EVP_MAX_BLOCK_LENGTH;

    class CryptoGuardCtx::Impl
    {
    public:
        Impl(Impl &&) = default;
        Impl &operator=(Impl &&) = default;
        ~Impl() = default;

        Impl(const Impl &) = delete;
        Impl &operator=(const Impl &) = delete;

        Impl(std::iostream &in, std::string_view password, bool iFlag)
            : _ctx(nullptr),
              _ready(false)
        {
            OpenSSL_add_all_algorithms();
            auto params = details::CreateChiperParamsFromPassword(password);
            params.encrypt = static_cast<int>(iFlag);

            _ctx.reset(EVP_CIPHER_CTX_new());
            if (!_ctx)
                throw std::runtime_error("Failed to create EVP context");

            if (EVP_CipherInit_ex(_ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) != 1)
                throw std::runtime_error("EVP_CipherInit_ex");

            if (EVP_CIPHER_CTX_set_padding(_ctx.get(), 1) != 1)
                throw std::runtime_error("EVP_CIPHER_CTX_set_padding");

            std::array<std::byte, OUT_BUF_SIZE> outBuf;
            std::array<std::byte, IN_BUF_SIZE> inBuf;
            int outLen;

            while (in.read(reinterpret_cast<char*>(inBuf.data()), IN_BUF_SIZE))
            {
                std::streamsize readLen = in.gcount();
                if (readLen <= 0) break;

                if (EVP_CipherUpdate(_ctx.get(),
                                     reinterpret_cast<unsigned char *>(outBuf.data()),
                                     &outLen, reinterpret_cast<unsigned char *>(inBuf.data()),
                                     static_cast<int>(readLen)) != 1)
                    throw std::runtime_error("EVP_CipherUpdate failed");

                _out.insert(_out.end(), outBuf.begin(), outBuf.begin() + outLen);
            }

            if (in.bad())
                throw std::runtime_error("Read error");

            if (EVP_CipherFinal_ex(_ctx.get(), reinterpret_cast<unsigned char *>(outBuf.data()), &outLen) != 1)
                throw std::runtime_error("EVP_CipherFinal_ex failed");

            _out.insert(_out.end(), outBuf.begin(), outBuf.begin() + outLen);

            _ready = true;
        }

        bool IsReady() const noexcept
        {
            return _ready;
        }

        std::vector<std::byte> &&GetResult() noexcept
        {
            _ready = false;
            return std::move(_out);
        }

    private:
        struct Deleter
        {
            void operator()(EVP_CIPHER_CTX *ptr)
            {
                EVP_CIPHER_CTX_free(ptr);
                EVP_cleanup();
            }
        };

        using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, Deleter>;

        std::vector<std::byte> _out;
        CtxPtr _ctx;
        bool _ready;
    };
#pragma endregion
//////////////////////////////////////////////////////////////////////////////////
#pragma region CryptoGuardCtx
    CryptoGuardCtx::CryptoGuardCtx() : pImpl_(nullptr) {}
    CryptoGuardCtx::~CryptoGuardCtx() = default;

    void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
    {
        pImpl_ = std::make_unique<Impl>(inStream, password, true);
        if (pImpl_->IsReady())
        {
            auto data = pImpl_->GetResult();
            if (!data.empty())
                outStream.write(reinterpret_cast<const char*>(data.data()), data.size());
        }
    }
    void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
    {
        pImpl_ = std::make_unique<Impl>(inStream, password, false);
        if (pImpl_->IsReady())
        {
            auto data = pImpl_->GetResult();
            if (!data.empty())
                outStream.write(reinterpret_cast<const char*>(data.data()), data.size());
        }
    }
    std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
#pragma endregion
} // namespace CryptoGuard
#pragma endregion
//////////////////////////////////////////////////////////////////////////////////
