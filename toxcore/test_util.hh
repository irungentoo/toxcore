#ifndef C_TOXCORE_TOXCORE_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_TEST_UTIL_H

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <vector>

template <typename T, void (*Delete)(T *)>
struct Function_Deleter {
    void operator()(T *ptr) const { Delete(ptr); }
};

// No default deleter, because we want to catch when we forget to specialise this one.
template <typename T>
struct Deleter;

template <typename T>
using Ptr = std::unique_ptr<T, Deleter<T>>;

template <typename Func, typename Class>
struct Method;

template <typename R, typename Class, typename... Args>
struct Method<R(void *, Args...), Class> {
    template <R (Class::*M)(void *, Args...)>
    static R invoke(void *self, Args... args)
    {
        return (static_cast<Class *>(self)->*M)(self, args...);
    }
};

template <typename T, std::size_t N>
std::array<T, N> to_array(T const (&arr)[N])
{
    std::array<T, N> stdarr;
    std::copy(arr, arr + N, stdarr.begin());
    return stdarr;
}

template <std::size_t N, typename T, typename... Args>
auto array_of(T &&make, Args... args)
{
    std::array<std::invoke_result_t<T, Args...>, N> arr;
    for (auto &elem : arr) {
        elem = make(args...);
    }
    return arr;
}

template <typename T, typename... Args>
auto vector_of(std::size_t n, T &&make, Args... args)
{
    std::vector<std::invoke_result_t<T, Args...>> vec;
    for (std::size_t i = 0; i < n; ++i) {
        vec.push_back(make(args...));
    }
    return vec;
}

template <typename Container, typename Less>
Container sorted(Container arr, Less less)
{
    std::sort(arr.begin(), arr.end(), less);
    return arr;
}

template <typename T>
T *require_not_null(const char *file, int line, T *ptr)
{
    if (ptr == nullptr) {
        std::fprintf(stderr, "unexpected null pointer at %s:%d\n", file, line);
        std::exit(7);
    }
    return ptr;
}

#define REQUIRE_NOT_NULL(ptr) require_not_null(__FILE__, __LINE__, ptr)

#endif  // C_TOXCORE_TOXCORE_TEST_UTIL_H
