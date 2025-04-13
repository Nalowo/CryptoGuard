#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>
#include <fstream>
#include <filesystem>

#pragma region details
namespace details
{
    using namespace std::literals;
    namespace fs = std::filesystem;

    template <typename... T>
    fs::path IsValidAndCleanPath(std::string_view inputPath)
    {
        fs::path res = fs::canonical(fs::path(inputPath));
        
        if (!fs::exists(res))
            throw std::runtime_error(std::format("File not exist: {}"sv, res.string()));

        if (!fs::is_regular_file(res))
            throw std::runtime_error(std::format("This is not file: "sv, res.string()));
        
        return res;
    }

    std::fstream OpenFile(std::string_view iPath, std::ios::openmode iMode)
    {
        namespace fs = std::filesystem;
        std::fstream res(IsValidAndCleanPath(iPath), iMode);
        res.exceptions(std::ofstream::failbit | std::ofstream::badbit);
        if (!res)
            throw std::runtime_error(std::format("Can`t open file: {}"sv, iPath));
        return res;
    }
} // namespace details
#pragma endregion

int main(int argc, char *argv[])
{
    try
    {
        CryptoGuard::ProgramOptions options;
        if (!options.Parse(argc, argv))
            return 1;

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        auto process = [&options](auto&& serv)
        {
            auto fsi = details::OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            auto fso = details::OpenFile(options.GetOutputFile(), std::ios::out | std::ios::trunc | std::ios::binary);
            serv(fsi, fso, options.GetPassword());
        };

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand())
        {
        case COMMAND_TYPE::ENCRYPT:
        {
            process([&cryptoCtx, &options](auto& fsi, auto& fso, auto password)
            {
                cryptoCtx.EncryptFile(fsi, fso, password);
            });
            std::print("File encoded successfully\n");
        }
            break;

        case COMMAND_TYPE::DECRYPT:
        {
            process([&cryptoCtx, &options](auto& fsi, auto& fso, auto password)
            {
                cryptoCtx.DecryptFile(fsi, fso, password);
            });
            std::print("File decoded successfully\n");
        }
            break;

        case COMMAND_TYPE::CHECKSUM:
        {
            auto fsi = details::OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(fsi));
        }
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    }
    catch (const std::exception &e)
    {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}