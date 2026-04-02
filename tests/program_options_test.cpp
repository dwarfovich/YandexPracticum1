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

}  // namespace CryptoGuard