#include "program_options.h"

namespace CryptoGuard {

const std::unordered_map<std::string, ProgramOptions::COMMAND_TYPE> ProgramOptions::commandMapping_ = {
    {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
    {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
    {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
};

boost::program_options::options_description ProgramOptions::GenerateDescription() {
    namespace po = boost::program_options;
    po::options_description description("Options:");
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

ProgramOptions::ProgramOptions() {}

ProgramOptions::~ProgramOptions() = default;

auto ProgramOptions::CommandFromString(const std::string &command) const -> COMMAND_TYPE {
    return commandMapping_.at(command);
}

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, description_), vm);
    po::notify(vm);

}
}  // namespace CryptoGuard
