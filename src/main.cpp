#include "crypto_guard_ctx.h"
#include "program_options.h"

#include <iostream>
#include <string>
#include <fstream>

void PerformCipherOperation(const CryptoGuard::ProgramOptions &options) {
    using namespace CryptoGuard;
    CryptoGuardCtx context;
    std::ifstream inFile{std::string(options.GetInputFile())};
    std::ofstream outFile{std::string(options.GetOutputFile())};
    if (options.GetCommand() == ProgramOptions::COMMAND_TYPE::ENCRYPT){
        context.EncryptFile(inFile, outFile, options.GetPassword());
    } else {
        context.DecryptFile(inFile, outFile, options.GetPassword());
    }
}

std::string CalculateChecksum(const CryptoGuard::ProgramOptions &options) {
    using namespace CryptoGuard;
    CryptoGuardCtx context;
    std::ifstream inFile{std::string(options.GetInputFile())};

    return context.CalculateChecksum(inFile);
}

int main(int argc, char *argv[]) {
    using namespace CryptoGuard;
    ProgramOptions options;
    try {
        const auto &message = options.Parse(argc, argv);
        if (options.GetParsingStatus() != ProgramOptions::PARSING_STATUS::SUCCESS) {
            std::cerr << message << '\n';
            return -1;
        }
        if (!message.empty()) {
            std::cout << message << '\n';
        }

        if (options.GetCommand() == ProgramOptions::COMMAND_TYPE::CHECKSUM){
            std::cout << "Checksum: " << CalculateChecksum(options) << '\n';
        } else{
            PerformCipherOperation(options);
            std::cout << "Done!\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "An error occured during process of your command: " << e.what() << '\n';
    }

    return 0;
}