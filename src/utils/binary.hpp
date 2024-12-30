#pragma once

#include <filesystem>
#include <fstream>

#include <utils/types.hpp>


namespace utils::binary {

// using BinaryByteT = uint8_t;
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

/// @class std::ifstream wrapper for binary I/O.
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

    /// @brief Reads a single value of a type T from the file.
    /// @tparam T value type
    /// @param value ref to value destination
    /// @return ref to self
    template<typename T>
    BinaryStreamReader& operator>>(T& value) {
        constexpr size_t buffer_size = sizeof(T);
        stream_.read(reinterpret_cast<BinaryByteT*>(&value), buffer_size);
        return *this;
    }

    /// @brief Reads `size` bytes to an already allocated buffer.
    /// @param buffer pointer to the beginning of the buffer. Buffer must be able to store at least `size` bytes
    void read(BinaryByteT* buffer, size_t size) {
        stream_.read(buffer, size);
    }

private:
    // BinaryStreamReader(const BinaryStreamReader& other);
    // BinaryStreamReader& operator=(const BinaryStreamReader& other);
    void Init();

    StreamT stream_;
};

} // namespace utils::binary
