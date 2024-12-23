#pragma once

namespace utils::types {

class NonCopyable {
    NonCopyable(NonCopyable&);
    NonCopyable& operator=(NonCopyable&);
};

} // namespace utils::types
