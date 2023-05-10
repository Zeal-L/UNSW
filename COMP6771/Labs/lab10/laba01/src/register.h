#ifndef COMP6771_REGISTER_H
#define COMP6771_REGISTER_H

#include <cstdint>
#include <type_traits>

template<auto I>
struct size2reg {
	using type = std::conditional_t<
	    I == 1,
	    std::uint8_t,
	    std::conditional_t<
	        I == 2,
	        std::uint16_t,
	        std::conditional_t<(2 < I) && (I <= 4), std::uint32_t, std::conditional_t<(4 < I) && (I <= 8), std::uint64_t, void>>>>;
};

template<auto I>
using size2reg_t = typename size2reg<I>::type;

template <typename T>
struct is_passable_in_register {
    static constexpr bool value =
        std::is_fundamental_v<T> ||
        (std::is_trivial_v<T> && sizeof(T) <= sizeof(void*));
};

template <typename T>
constexpr bool is_passable_in_register_v = is_passable_in_register<T>::value;

#endif // COMP6771_REGISTER_H
