#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <string>

using namespace CryptoGuard;

class CryptoGuardCtxTest : public ::testing::Test {
protected:
    const std::string password = "test_password";
    const std::string test_data = "Hello, Crypto!";
};

TEST_F(CryptoGuardCtxTest, EncryptProducesData) {
    std::stringstream input(test_data);
    std::stringstream output;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(input, output, password);

    ASSERT_GT(output.str().size(), 0);
}

TEST_F(CryptoGuardCtxTest, DecryptRestoresOriginal) {
    std::stringstream input(test_data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(input, encrypted, password);

    std::string encrypted_data = encrypted.str();
    assert(encrypted_data.size() % 16 == 0);
    std::stringstream encrypted_stream(encrypted_data);
    ctx.DecryptFile(encrypted_stream, decrypted, password);

    auto str = decrypted.str();
    ASSERT_EQ(decrypted.str(), test_data);
}

TEST_F(CryptoGuardCtxTest, EncryptSameInputGivesSameOutput) {
    std::stringstream input1(test_data);
    std::stringstream input2(test_data);
    std::stringstream output1;
    std::stringstream output2;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(input1, output1, password);
    ctx.EncryptFile(input2, output2, password);

    ASSERT_EQ(output1.str(), output2.str());
}

TEST_F(CryptoGuardCtxTest, DecryptWithWrongPasswordFails) {
    std::stringstream input(test_data);
    std::stringstream encrypted;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(input, encrypted, password);

    std::string encrypted_data = encrypted.str();
    std::stringstream encrypted_stream(encrypted_data);
    std::stringstream decrypted;

    ASSERT_THROW(ctx.DecryptFile(encrypted_stream, decrypted, "wrong_password"), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, EncryptEmptyInputProducesEmptyOutput) {
    std::stringstream input;
    std::stringstream output;

    CryptoGuardCtx ctx;
    ASSERT_THROW({ ctx.EncryptFile(input, output, password); }, std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, ReuseObjectForEncryption) {
    std::stringstream input1("Data One");
    std::stringstream output1;

    std::stringstream input2("Data Two");
    std::stringstream output2;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(input1, output1, password);
    ctx.EncryptFile(input2, output2, password);

    ASSERT_NE(output1.str(), output2.str());
    ASSERT_GT(output1.str().size(), 0);
    ASSERT_GT(output2.str().size(), 0);
}

TEST(CryptoGuardCtxTests, DecryptsEncryptedStreamCorrectly) {
    std::stringstream plaintextStream("Test message for encryption.");
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;
    const std::string password = "securepassword";

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(plaintextStream, encryptedStream, password);

    // Сбросить указатель потока на начало
    encryptedStream.seekg(0);

    ctx.DecryptFile(encryptedStream, decryptedStream, password);
    decryptedStream.seekg(0);

    std::string decryptedContent;
    std::getline(decryptedStream, decryptedContent);
    ASSERT_EQ(decryptedContent, "Test message for encryption.");
}

TEST(CryptoGuardCtxTests, ThrowsOnWrongPassword) {
    std::stringstream plaintextStream("Secret text");
    std::stringstream encryptedStream;
    std::stringstream outputStream;

    const std::string correctPassword = "correct";
    const std::string wrongPassword = "wrong";

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(plaintextStream, encryptedStream, correctPassword);
    encryptedStream.seekg(0);

    ASSERT_THROW(
        {
            CryptoGuard::CryptoGuardCtx ctx2;
            ctx2.DecryptFile(encryptedStream, outputStream, wrongPassword);
        },
        std::runtime_error);
}

TEST(CryptoGuardCtxTests, ThrowsOnEmptyInputDecryption) {
    std::stringstream emptyInput;
    std::stringstream output;
    const std::string password = "irrelevant";

    ASSERT_THROW(
        {
            CryptoGuard::CryptoGuardCtx ctx;
            ctx.DecryptFile(emptyInput, output, password);
        },
        std::runtime_error);
}

TEST(CryptoGuardCtxChecksumTests, CalculateChecksum_ValidInput_ReturnsExpectedHash) {
    std::stringstream input("hello world");
    CryptoGuardCtx ctx;
    std::string checksum = ctx.CalculateChecksum(input);

    // Проверка контрольной суммы "hello world" в hex (sha256)
    EXPECT_EQ(checksum, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(CryptoGuardCtxChecksumTests, CalculateChecksum_EmptyInput_ThrowsException) {
    std::stringstream input("");
    CryptoGuardCtx ctx;
    EXPECT_THROW({ ctx.CalculateChecksum(input); }, std::runtime_error);
}

TEST(CryptoGuardCtxChecksumTests, CalculateChecksum_SameInput_SameChecksum) {
    std::stringstream input1("repeatable input");
    std::stringstream input2("repeatable input");

    CryptoGuardCtx ctx1;
    CryptoGuardCtx ctx2;

    std::string hash1 = ctx1.CalculateChecksum(input1);
    std::string hash2 = ctx2.CalculateChecksum(input2);

    EXPECT_EQ(hash1, hash2);
}

TEST(CryptoGuardCtxChecksumTests, CalculateChecksum_DifferentInputs_DifferentChecksums) {
    std::stringstream input1("input A");
    std::stringstream input2("input B");

    CryptoGuardCtx ctx;
    std::string hash1 = ctx.CalculateChecksum(input1);
    std::string hash2 = ctx.CalculateChecksum(input2);

    EXPECT_NE(hash1, hash2);
}