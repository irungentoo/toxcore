/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUNC_CONVERSION_H
#define C_TOXCORE_TESTING_FUZZING_FUNC_CONVERSION_H

namespace detail {

template <typename F, F f>
struct func_conversion {
private:
    template <typename R, typename... Args>
    using func_pointer = R (*)(Args...);

    template <typename From>
    struct static_caster {
        From obj;

        template <typename To>
        operator To() const
        {
            return static_cast<To>(obj);
        }
    };

public:
    template <typename R, typename Arg, typename... Args>
    constexpr operator func_pointer<R, Arg, Args...>()
    {
        return [](Arg obj, auto... args) { return f(static_caster<Arg>{obj}, args...); };
    }
};

template <typename F>
struct make_funptr;

template <typename T, typename R, typename... Args>
struct make_funptr<R (T::*)(Args...) const> {
    using type = R (*)(Args...);
};

/** @brief Turn a memfunptr type into a plain funptr type.
 *
 * Not needed in C++20, because we can pass the lambda itself as template
 * argument, but in C++17, we need to do an early conversion.
 */
template <typename F>
using make_funptr_t = typename make_funptr<F>::type;

}

/** @brief Turn a C++ lambda into a C function pointer with `void*` param.
 *
 * Takes a lambda function with any pointer type as first parameter and turns it
 * into a C function pointer with `void*` as the first parameter. Internally, it
 * `static_cast`s that `void*` to the lambda's parameter type, avoiding a bunch
 * of casts inside the lambdas.
 *
 * This works on any type `T` that can be `static_cast` to `U`, not just `void*`
 * to `U*`, but the common case for C callbacks is `void*`.
 */
template <typename F>
static constexpr auto operator!(F f)
{
    return detail::func_conversion<detail::make_funptr_t<decltype(&F::operator())>, f>{};
}

#endif  // C_TOXCORE_TESTING_FUZZING_FUNC_CONVERSION_H
