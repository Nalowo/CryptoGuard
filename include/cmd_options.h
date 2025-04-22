#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {
namespace po = boost::program_options;
using namespace std::literals;

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    bool Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string_view GetInputFile() const { return inputFile_; }
    std::string_view GetOutputFile() const { return outputFile_; }
    std::string_view GetPassword() const { return password_; }

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt"sv, COMMAND_TYPE::ENCRYPT},
        {"decrypt"sv, COMMAND_TYPE::DECRYPT},
        {"checksum"sv, COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;
    po::options_description desc_;
};

}  // namespace CryptoGuard
