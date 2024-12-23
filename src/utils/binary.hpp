#pragma once

#include <filesystem>
#include <fstream>

#include <src/utils/types.hpp>


namespace utils::binary {

using BinaryByteT = char;

enum class BinaryStreamPosition {
    BEGIN = 0,
    END = 1,
};

/// @class Raised when trying to read binary file after EOF.
class EofException : public std::runtime_error {
public:
    EofException();
};

/// @class std::ifstream wrapper for binary I/O. Intended to read data stored via BinaryOutStream.
/// Binary stream wrappers provide formatted streams interface, but store data more compactly.
/// Main features are the following:
/// - storing numbers in binary format instead of formatted characters
/// - storing of dynamic containers (std::string, std::vector, etc.)
class BinaryStreamReader final : utils::types::NonCopyable {
public:
    using StreamT = std::basic_ifstream<BinaryByteT, std::char_traits<BinaryByteT>>;

    /// @brief ctor
    /// @param path wrappable file path 
    BinaryStreamReader(const std::filesystem::path& path);

    /// @brief ctor
    /// @param stream already opened file to wrap
    BinaryStreamReader(StreamT&& stream);

    /// @brief Move ctor
    /// @param other other stream instance
    BinaryStreamReader(BinaryStreamReader&& other);

    /// @brief dtor
    ~BinaryStreamReader();

    /// @brief Check whether the end of file was reached.
    bool Eof() const;

    /// @brief Seek the specified position in file
    void Seek(size_t position);

    /// @brief Seek the special position in file
    void Seek(BinaryStreamPosition position);

    /// @brief Move assignment operator
    /// @param other other stream
    /// @return ref to self
    BinaryStreamReader& operator=(BinaryStreamReader&& other);

    /// @brief Reads a single value of an arithmetic type T from the file.
    /// @tparam T value type
    /// @param value ref to value destination
    /// @return ref to self
    template<typename T>
    BinaryStreamReader& operator>>(T& value) {
        constexpr size_t buffer_size = sizeof(value);
        stream_.read(reinterpret_cast<BinaryByteT*>(&value), buffer_size);
        return *this;
    }

private:
    // BinaryStreamReader(const BinaryStreamReader& other);
    // BinaryStreamReader& operator=(const BinaryStreamReader& other);
    void Init();

    StreamT stream_;
};

} // namespace utils::binary
