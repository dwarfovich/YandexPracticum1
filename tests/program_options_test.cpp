#include "program_options.h"

#include <gtest/gtest.h>

namespace CryptoGuard {

TEST(ProgramOptionsTest, EmptyObject) {
    ProgramOptions options;

    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::UNEXPECTED_ERROR);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptionsTest, TestParsing_InsufficientParameters) {
    ProgramOptions options;
    const char* const args[] = {"--help"};

    options.Parse(1, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::NO_COMMAND_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_InsufficientParametersWithCommand) {
    ProgramOptions options;
    const char *const args[] = {"--command encrypt"};

    options.Parse(1, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::NO_COMMAND_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_Help) {
    ProgramOptions options;
    const char *const args[] = {"app", "--help"};

    options.Parse(2, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::SUCCESS);
}

TEST(ProgramOptionsTest, TestParsing_CommandWithoutValue) {
    ProgramOptions options;
    const char *const args[] = {"app", "--command"};

    options.Parse(2, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::UNEXPECTED_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_ShortCommandWithoutValue) {
    ProgramOptions options;
    const char *const args[] = {"app", "-c"};

    options.Parse(2, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::UNEXPECTED_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_CommandWithInvalidParameter) {
    ProgramOptions options;
    const char *const args[] = {"app", "--command=a"};

    options.Parse(2, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::INVALID_COMMAND_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_CommandWithInsufficientArguments) {
    ProgramOptions options;
    const char *const args[] = {"app", "--command=encrypt"};

    options.Parse(2, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::INVALID_ARGUMENTS_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_CommandWithInsufficientArguments2) {
    ProgramOptions options;
    const char *const args[] = {"app", "--command=encrypt", "--input=a"};

    auto a= options.Parse(3, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::INVALID_ARGUMENTS_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_InvalidCommandWithCorrectArguments) {
    ProgramOptions options;
    const char *const args[] = {"app", "--command=e", "--input=a", "--output=b", "--password=p"};

    options.Parse(5, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::INVALID_COMMAND_ERROR);
}

TEST(ProgramOptionsTest, TestParsing_Command) {
    ProgramOptions options;
    const char *const args[] = {"app", "--command=encrypt", "--input=a", "--output=b", "--password=p"};

    options.Parse(5, args);
    EXPECT_EQ(options.GetParsingStatus(), ProgramOptions::PARSING_STATUS::SUCCESS);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "a");
    EXPECT_EQ(options.GetOutputFile(), "b");
    EXPECT_EQ(options.GetPassword(), "p");
}

} // namespace CryptoGuard