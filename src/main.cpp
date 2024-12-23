#include <iostream>
#include <filesystem>


int main(int argc, char** argv) {

    if (argc != 2) {
        throw std::runtime_error("unexpected number of arguments");
    }

    auto source_path = std::filesystem::path(argv[1]);

    // 0. parse cmd args
    // 1. open and parse .pcap, extract payload
    // 2. parse simba payload
    // 3. cast to json
    // 4. output to screen / file

    std::cout << "hello world";

    return 0;
}
