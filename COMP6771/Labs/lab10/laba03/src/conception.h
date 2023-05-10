#ifndef COMP6771_CONCEPTION_H
#define COMP6771_CONCEPTION_H

#include <string>

// In this exercise we will explore how to create a concept modelling an animal. Animals should be able to:

// have a member function called cry(), which returns that animal's unique cry as a string i.e. "woof" for a dog, "nyaa" for a Japanese cat, "quack" for a duck, etc.
// have a member type called name_type which is a const char[8+3].
// be "regular".
template <typename A>
concept animal = requires(A a) {
    { a.cry() } -> std::same_as<std::string>;
    requires std::is_same_v<typename A::name_type, const char[8+3]>;
};

struct dog {
    auto cry() const -> std::string {
        return "woof";
    }

    using name_type = const char[8 + 3];
};

struct neko {
    auto cry() const -> std::string {
        return "nyaa";
    }

    using name_type = const char[8 + 3];
};

struct duck {
    auto cry() const -> std::string {
        return "quack";
    }

    using name_type = const char[8 + 3];
};

struct robot {
    using name_type = const char[8 + 3];
};

#endif // COMP6771_CONCEPTION_H
