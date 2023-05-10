#ifndef COMP6771_RATIONAL_OO_H
#define COMP6771_RATIONAL_OO_H

#include <optional>


class rational_number {
public:
    static std::optional<rational_number> null;

    static auto make_rational(int numerator, int denominator) -> std::optional<rational_number> {
        if (denominator == 0) {
            return null;
        } else {
            return std::optional<rational_number>{rational_number{numerator, denominator}};
        }
    }

    auto operator[](char c) const -> int;
    auto operator[](char c) -> int&;
    operator double() const;

    auto operator+(const rational_number &other) const -> rational_number;
    auto operator-(const rational_number &other) const -> rational_number;
    auto operator*(const rational_number &other) const -> rational_number;
    auto operator/(const rational_number &other) const -> std::optional<rational_number>;

    auto operator==(const rational_number &other) const -> bool;
    auto operator!=(const rational_number &other) const -> bool;

private:
    rational_number(int numerator, int denominator) : numerator_{numerator}, denominator_{denominator} {}

    int numerator_;
    int denominator_;
};

#endif // COMP6771_RATIONAL_OO_H
