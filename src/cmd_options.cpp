#include "cmd_options.h"
#include <format>
#include <iostream>
#include <print>

namespace CryptoGuard {
using namespace std::literals;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "produce help message")("command,c", po::value<std::string>(),
                                                          "Procedure command: encrypt, decrypt, checksum")(
        "input,i", po::value(&inputFile_)->multitoken()->value_name("file"s), "Input file to encrypt")(
        "output,o", po::value(&outputFile_)->multitoken()->value_name("file"s), "Output file with encrypted data")(
        "password,p", po::value(&password_)->multitoken()->value_name("string"s), "Password for data");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.empty()) {
            std::println("Type: \"CryptoGuard --help\" to get information"sv);
            return false;
        }

        if (vm.count("help")) {
            std::cout << desc_ << '\n';
            return false;
        }

        if (vm.contains("command")) {
            std::string_view command = vm["command"].as<std::string>();
            if (auto it = commandMapping_.find(command); it != commandMapping_.end()) {
                switch (it->second) {
                case COMMAND_TYPE::CHECKSUM:
                    if (inputFile_.empty())
                        throw std::runtime_error("Input file not set"s);
                    break;
                case COMMAND_TYPE::DECRYPT:
                case COMMAND_TYPE::ENCRYPT:
                    if (inputFile_.empty())
                        throw std::runtime_error("Input file not set"s);
                    if (outputFile_.empty())
                        throw std::runtime_error("Output file not set"s);
                    if (password_.empty())
                        throw std::runtime_error("Passord file not set"s);
                    break;
                default:
                    throw std::runtime_error(std::format("Unsupported command: {}"sv, command));
                }
                command_ = it->second;
            } else
                throw std::runtime_error(std::format("Unsupported command: {}"sv, command));
        } else
            throw std::runtime_error("Command not set"s);
    } catch (std::exception &e) {
        std::println("Error: {}"sv, e.what());
        return false;
    } catch (...) {
        std::println("Exception of unknown type!"sv);
        return false;
    }

    return true;
}
}  // namespace CryptoGuard
