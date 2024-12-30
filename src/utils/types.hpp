#pragma once

namespace utils::types {

class NonCopyable {
public:
    NonCopyable() = default;
private:
    NonCopyable(NonCopyable&);
    NonCopyable& operator=(NonCopyable&);
};

} // namespace utils::types
