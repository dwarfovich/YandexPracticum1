#include "program_options.h"

#include <boost/program_options/variables_map.hpp>

#include <sstream>

namespace CryptoGuard {

const std::unordered_map<std::string, ProgramOptions::COMMAND_TYPE> ProgramOptions::commandMapping_ = {
    {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
    {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
    {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
};

boost::program_options::options_description ProgramOptions::GenerateDescription() {
    namespace po = boost::program_options;
    po::options_description description("Options");
    // clang-format off
    description.add_options()
        ("help,h", "produce help message")
        ("command,c", po::value<std::string>(), "set command (encrypt, decrypt, checksum)")
        ("input,i", po::value<std::string>(), "set input file")
        ("output,o", po::value<std::string>(), "set output file")
        ("password,p", po::value<std::string>(), "set password");
    // clang-format on
    return description;
}

auto ProgramOptions::CommandFromString(const std::string &command) const -> COMMAND_TYPE {
    return commandMapping_.at(command);
}

std::string ProgramOptions::DescriptionText() const {
    std::ostringstream iss;
    description_.print(iss);
    return iss.str();
}

std::string ProgramOptions::ParseCommand(const boost::program_options::variables_map &vars_map) noexcept {
    const auto &commandStr = vars_map["command"].as<std::string>();
    try {
        command_ = CommandFromString(commandStr);
        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            inputFile_ = vars_map["input"].as<std::string>();
            outputFile_ = vars_map["output"].as<std::string>();
            password_ = vars_map["password"].as<std::string>();
        } else if (command_ == COMMAND_TYPE::CHECKSUM) {
            inputFile_ = vars_map["input"].as<std::string>();
        }
    } catch (const std::out_of_range &e) {
        parsingStatus_ = PARSING_STATUS::INVALID_COMMAND_ERROR;
        return "Invalid command: " + commandStr + '\n' + DescriptionText();
    } catch(const std::exception& e){
        parsingStatus_ = PARSING_STATUS::INVALID_ARGUMENTS_ERROR;
        return "Wrong command arguments.\n" + DescriptionText();
    }

    return std::string();
}

std::string ProgramOptions::Parse(int argc, char *argv[]) noexcept
{
    parsingStatus_ = PARSING_STATUS::SUCCESS;
    namespace po = boost::program_options;
    po::variables_map vars_map;
    try {
        po::store(po::parse_command_line(argc, argv, description_), vars_map);
        po::notify(vars_map);
    } catch (const po::error &e) {
        parsingStatus_ = PARSING_STATUS::UNEXPECTED_ERROR;
        return std::string("Error parsing command line: ") + e.what() + "\n" + DescriptionText();
    }

    if (vars_map.count("help")) {
        return DescriptionText();
    }

    std::string responseMessage;
    if (vars_map.count("command")) {
        return ParseCommand(vars_map);
    } else {
        parsingStatus_ = PARSING_STATUS::NO_COMMAND_ERROR;
        return "Command is required.\n" + DescriptionText();
    }
}

}  // namespace CryptoGuard
