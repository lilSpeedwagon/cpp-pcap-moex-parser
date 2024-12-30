#include <iostream>
#include <filesystem>

#include <parsers/pcap/pcap_parser.h>


int main(int argc, char** argv) {
    // 0. parse cmd args
    // 1. open and parse .pcap, extract payload
    // 2. parse simba payload
    // 3. cast to json
    // 4. output to screen / file

    if (argc != 2) {
        throw std::runtime_error("unexpected number of arguments");
    }
    auto source_path = std::filesystem::path(argv[1]);

    parsers::pcap::PCAPParser parser(source_path);
    auto pcap_packets = parser.read_all();

    std::cout << pcap_packets.size() << " packets red";

    return 0;
}
