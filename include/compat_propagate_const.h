#if __has_include(<experimental/propagate_const>)
#include <experimental/propagate_const>
namespace CryptoGuard {
template <typename T>
using propagate_const = std::experimental::propagate_const<T>;
}
#else
#include <utility>

namespace CryptoGuard {
template <typename T>
class propagate_const {
public:
    propagate_const() = default;
    propagate_const(T ptr) : ptr_(std::move(ptr)) {}

    // Access
    T &get() { return ptr_; }
    const T &get() const { return ptr_; }

    auto operator->() { return ptr_.operator->(); }
    auto operator->() const { return ptr_.operator->(); }

    auto &operator*() { return *ptr_; }
    const auto &operator*() const { return *ptr_; }

    operator T &() { return ptr_; }
    operator const T &() const { return ptr_; }

private:
    T ptr_;
};

}  // namespace CryptoGuard
#endif