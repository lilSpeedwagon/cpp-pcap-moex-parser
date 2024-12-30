#include "binary.hpp"

#include <cstring>


namespace utils::binary {

namespace {

static const std::ios_base::openmode kFileReadMode = std::ios::binary | std::ios::in;

void SetupStreamExceptions(
    std::basic_ios<BinaryByteT, std::char_traits<BinaryByteT>>& stream) {
    stream.exceptions(
        std::ifstream::failbit | std::ifstream::eofbit | std::ifstream::badbit);
}

} // namespace

EofException::EofException() : std::runtime_error("end of binary file is reached") {}

BinaryStreamReader::BinaryStreamReader(const std::filesystem::path& path)
    : stream_(path, kFileReadMode) {
    Init();
}

BinaryStreamReader::BinaryStreamReader(StreamT&& stream) 
    : stream_(std::move(stream)) {
    Init();
}

BinaryStreamReader::BinaryStreamReader(BinaryStreamReader&& other) {
    std::swap(stream_, other.stream_);
}

BinaryStreamReader::~BinaryStreamReader() {}

bool BinaryStreamReader::Eof() const {
    return stream_.eof();
}

void BinaryStreamReader::Seek(size_t position) {
    stream_.seekg(position);
}

void BinaryStreamReader::Seek(BinaryStreamPosition position) {
    switch (position) {
        case BinaryStreamPosition::BEGIN:
            stream_.seekg(0, std::ios_base::beg);
            break;
        case BinaryStreamPosition::END:
            stream_.seekg(0, std::ios_base::end);
            break;
        default:
            throw std::logic_error("Unknown BinaryStreamReader position");
    }
}

BinaryStreamReader& BinaryStreamReader::operator=(BinaryStreamReader&& other) {
    std::swap(stream_, other.stream_);
    return *this;
}

void BinaryStreamReader::Init() {
    SetupStreamExceptions(stream_);
    Seek(BinaryStreamPosition::BEGIN);
}

} // namespace common::binary