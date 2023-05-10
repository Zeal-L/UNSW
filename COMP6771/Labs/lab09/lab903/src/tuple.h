#ifndef COMP6771_TUPLE_H
#define COMP6771_TUPLE_H

#include <cstddef>

template <typename... Ts>
struct tuple;

template <typename T>
struct tuple<T> {
    T elem;
};

template <typename T, typename... Ts>
struct tuple<T, Ts...> {
    T elem;
    tuple<Ts...> cons;
};

template<typename T>
tuple(T) -> tuple<T>;

template<typename T, typename... Ts>
tuple(T, Ts...) -> tuple<T, Ts...>;


template <std::size_t I, typename T, typename ...Ts>
auto get(const tuple<T, Ts...> &tp) {
    if constexpr (I == 0) {
        return tp.elem;
    } else {
        return get<I - 1>(tp.cons);
    }
}

#endif // COMP6771_TUPLE_H
