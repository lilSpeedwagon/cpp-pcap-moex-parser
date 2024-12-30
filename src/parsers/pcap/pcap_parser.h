#pragma once

#include <bitset>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <list>
#include <optional>
#include <vector>

#include <utils/binary.hpp>

namespace parsers::pcap {

namespace {

static constexpr const uint32_t kMagicNumberMsec = 0xA1B2C3D4;
static constexpr const uint32_t kMagicNumberNsec = 0xA1B23C4D;

enum class PCAPTimestampsFormat {
    SecondsNanoseconds,
    SecondsMicroseconds,
};

struct PCAPHeader {
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t reserved;
    uint32_t snap_len;
    std::bitset<3> fcs;
    std::bitset<1> f;
    std::bitset<12> fcs_padding;
    uint16_t frame_check_seq;
    uint16_t link_type;
};

struct PCAPPacketHeader {
    uint32_t timestamp;
    uint32_t timestamp_fraction;
    uint32_t captured_packet_length;
    uint32_t original_packet_length;
};

struct PCAPPacket {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::chrono::nanoseconds timestamp_fraction;
    std::vector<char> payload;
};

} // namespace

class PCAPParser {
public:
    PCAPParser(const std::filesystem::path& path)
        : reader_(path), timestamps_format_{}, snap_len_{}, link_type_{}, fcs_size_opt_{} {
        read_header();
    }
    PCAPParser(PCAPParser&& other);
    PCAPParser& operator=(PCAPParser&& other);
    ~PCAPParser() = default;

    PCAPPacket read_next() {
        return read_package();
    }

    std::list<PCAPPacket> read_all() {
        std::list<PCAPPacket> result;
        while (!reader_.Eof()) {
            result.emplace_back(read_next());
        }
        return result;
    }

private:
    void read_header() {
        try {
            PCAPHeader header{};
            reader_ >> header;

            // Validate magic number.
            switch (header.magic_number)
            {
            case kMagicNumberMsec:
                timestamps_format_ = PCAPTimestampsFormat::SecondsMicroseconds;
                break;
            case kMagicNumberNsec:
                timestamps_format_ = PCAPTimestampsFormat::SecondsNanoseconds;
                break;
            default:
                throw std::runtime_error("invalid magic number");
            }

            // Validate frame check sequence.
            // If 4d bit of "frame_check_seq" is set to 1, then the first 3 bits represent
            // the number of 16-bit (2 byte) words of FCS that are appended to each packet.
            if (header.f[0]) {
                fcs_size_opt_ = *(reinterpret_cast<uint8_t*>(&header.fcs));
            }

            snap_len_ = header.snap_len;
            link_type_ = header.link_type;
        } catch (const std::exception& err) {
            throw std::runtime_error("invalid PCAP header");
        }
    }

    PCAPPacket read_package() {
        // Read packet header.
        PCAPPacketHeader header;
        reader_ >> header;

        // Convert timestamps.
        auto timestamp = std::chrono::system_clock::from_time_t(header.timestamp);
        std::chrono::nanoseconds timestamp_fraction(header.timestamp_fraction); 
        if (timestamps_format_ == PCAPTimestampsFormat::SecondsMicroseconds) {
            timestamp_fraction *= 1000;
        }

        // Read the next "captured_packet_length" bytes as packet payload.
        std::vector<char> packet_data(header.captured_packet_length);
        reader_.read(packet_data.data(), header.captured_packet_length);

        return PCAPPacket{
            std::move(timestamp),
            std::move(timestamp_fraction),
            std::move(packet_data),
        };
    }

    utils::binary::BinaryStreamReader reader_;
    PCAPTimestampsFormat timestamps_format_;
    uint32_t snap_len_;
    uint16_t link_type_;
    std::optional<uint8_t> fcs_size_opt_;
};

} // namespace parsers::pcap
