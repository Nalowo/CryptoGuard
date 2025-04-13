#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include "crypto_guard_ctx.h"

using namespace CryptoGuard;

class CryptoGuardCtxFixture : public ::testing::Test {
protected:
    std::string password = "supersecure";
    CryptoGuardCtx ctx;

    void Encrypt(const std::string& input, std::stringstream& out) {
        std::stringstream in(input);
        ctx.EncryptFile(in, out, password);
    }

    void Decrypt(std::stringstream& in, std::string& out) {
        std::stringstream result;
        ctx.DecryptFile(in, result, password);
        out = result.str();
    }
};

TEST_F(CryptoGuardCtxFixture, EncryptThenDecryptReturnsOriginal)
{
    std::string input = "The quick brown fox";
    std::stringstream encrypted;
    std::string decrypted;

    Encrypt(input, encrypted);
    encrypted.seekg(0);
    Decrypt(encrypted, decrypted);

    EXPECT_EQ(decrypted, input);
}

TEST_F(CryptoGuardCtxFixture, EncryptDecryptEmptyInput)
{
    std::string input = "";
    std::stringstream encrypted;
    std::string decrypted;

    Encrypt(input, encrypted);
    encrypted.seekg(0);
    Decrypt(encrypted, decrypted);

    EXPECT_EQ(decrypted, input);
}

TEST_F(CryptoGuardCtxFixture, DecryptWithWrongPasswordThrows)
{
    std::string input = "Sensitive data";
    std::stringstream encrypted;

    Encrypt(input, encrypted);
    encrypted.seekg(0);

    std::stringstream result;
    EXPECT_THROW({
        CryptoGuardCtx wrongCtx;
        wrongCtx.DecryptFile(encrypted, result, "wrongpass");
    }, std::runtime_error);
}

TEST_F(CryptoGuardCtxFixture, ReuseForMultipleEncryptions)
{
    std::string text1 = "first";
    std::string text2 = "second";

    std::stringstream enc1, enc2;
    std::string dec1, dec2;

    Encrypt(text1, enc1);
    enc1.seekg(0);
    Decrypt(enc1, dec1);

    Encrypt(text2, enc2);
    enc2.seekg(0);
    Decrypt(enc2, dec2);

    EXPECT_EQ(dec1, text1);
    EXPECT_EQ(dec2, text2);
}

TEST_F(CryptoGuardCtxFixture, EncryptDecryptSpecialCharacters)
{
    std::string input = "\x00\xFF\xA5\n\tTest\x7F\x01";
    std::stringstream encrypted;
    std::string decrypted;

    Encrypt(input, encrypted);
    encrypted.seekg(0);
    Decrypt(encrypted, decrypted);

    EXPECT_EQ(decrypted, input);
}

TEST_F(CryptoGuardCtxFixture, DecryptTwiceReturnsSameResult)
{
    std::string input = "Same input";
    std::stringstream encrypted;
    std::string decrypted1, decrypted2;

    Encrypt(input, encrypted);

    std::stringstream copyEncrypted(encrypted.str());
    encrypted.seekg(0);
    copyEncrypted.seekg(0);

    Decrypt(encrypted, decrypted1);
    Decrypt(copyEncrypted, decrypted2);

    EXPECT_EQ(decrypted1, input);
    EXPECT_EQ(decrypted2, input);
    EXPECT_EQ(decrypted1, decrypted2);
}
