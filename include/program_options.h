#pragma once

#include <boost/program_options.hpp>

#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };
    enum class PARSING_STATUS {
        SUCCESS,
        UNEXPECTED_ERROR,
        NO_COMMAND_ERROR,
        INVALID_COMMAND_ERROR,
        INVALID_ARGUMENTS_ERROR,
    };

    std::string Parse(int argc, const char * const argv[]) noexcept;

    PARSING_STATUS GetParsingStatus() const noexcept { return parsingStatus_; }
    COMMAND_TYPE GetCommand() const noexcept { return command_; }
    std::string_view GetInputFile() const noexcept { return inputFile_; }
    std::string_view GetOutputFile() const noexcept { return outputFile_; }
    std::string_view GetPassword() const noexcept { return password_; }

private:  // methods
    COMMAND_TYPE CommandFromString(const std::string &command) const;
    std::string DescriptionText() const;
    std::string ParseCommand(const boost::program_options::variables_map &vars_map) noexcept;

private:  // data
    using options_description = boost::program_options::options_description;
    static options_description GenerateDescription();
    inline static const options_description description_ = GenerateDescription();
    static const std::unordered_map<std::string, COMMAND_TYPE> commandMapping_;

    PARSING_STATUS parsingStatus_ = PARSING_STATUS::UNEXPECTED_ERROR;
    COMMAND_TYPE command_ = COMMAND_TYPE::ENCRYPT;
    std::string inputFile_;
    std::string outputFile_;
    std::string password_;
};

}  // namespace CryptoGuard
