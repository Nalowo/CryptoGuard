#include "cmd_options.h"
#include <gtest/gtest.h>

using namespace CryptoGuard;

class ProgramOptionsTest : public ::testing::Test {
protected:
    ProgramOptions options;

    static std::vector<char *> ToArgv(const std::vector<std::string> &args, std::vector<std::string> &storage) {
        storage = args;
        std::vector<char *> argv;
        for (auto &s : storage)
            argv.push_back(s.data());
        return argv;
    }
};

// Тест 1: Проверка помощи
TEST_F(ProgramOptionsTest, HelpOptionPrintsHelpAndReturnsFalse) {
    std::vector<std::string> storage;
    auto argv = ToArgv({"CryptoGuard", "--help"}, storage);
    EXPECT_FALSE(options.Parse(argv.size(), argv.data()));
}

// Тест 2: Ошибка при отсутствии команды
TEST_F(ProgramOptionsTest, MissingCommandReturnsFalse) {
    std::vector<std::string> storage;
    auto argv = ToArgv({"CryptoGuard", "--input", "in.txt"}, storage);
    EXPECT_FALSE(options.Parse(argv.size(), argv.data()));
}

// Тест 3: Ошибка при неизвестной команде
TEST_F(ProgramOptionsTest, InvalidCommandReturnsFalse) {
    std::vector<std::string> storage;
    auto argv = ToArgv({"CryptoGuard", "--command", "compress"}, storage);
    EXPECT_FALSE(options.Parse(argv.size(), argv.data()));
}

// Тест 4: Ошибка при команде encrypt без обязательных аргументов
TEST_F(ProgramOptionsTest, EncryptMissingArgumentsReturnsFalse) {
    std::vector<std::string> storage;
    auto argv = ToArgv({"CryptoGuard", "--command", "encrypt", "--input", "in.txt"}, storage);
    EXPECT_FALSE(options.Parse(argv.size(), argv.data()));
}

// Тест 5: Успешный парсинг команды encrypt
TEST_F(ProgramOptionsTest, ValidEncryptCommandParsesCorrectly) {
    std::vector<std::string> storage;
    auto argv = ToArgv(
        {"CryptoGuard", "--command", "encrypt", "--input", "in.txt", "--output", "out.txt", "--password", "1234"},
        storage);
    ASSERT_TRUE(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

// Тест 6: Успешный парсинг команды checksum
TEST_F(ProgramOptionsTest, ValidChecksumCommandParsesCorrectly) {
    std::vector<std::string> storage;
    auto argv = ToArgv({"CryptoGuard", "--command", "checksum", "--input", "data.txt"}, storage);
    ASSERT_TRUE(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "data.txt");
}
