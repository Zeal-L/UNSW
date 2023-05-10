#ifndef COMP6771_RATIONAL_H
#define COMP6771_RATIONAL_H

#include <optional>

class rational_number {
    private:
        int numerator_;
        int denominator_;
        rational_number(int num, int denom) : numerator_{num}, denominator_{denom} {};

    public:
        static std::optional<rational_number> null;
        static auto make_rational(int num, int denom) -> std::optional<rational_number>;
        auto value() const -> double;
        friend auto add(rational_number const& lhs, rational_number const& rhs) -> rational_number;
        friend auto sub(rational_number const& lhs, rational_number const& rhs) -> rational_number;
        friend auto mul(rational_number const& lhs, rational_number const& rhs) -> rational_number;
        friend auto div(rational_number const& lhs, rational_number const& rhs) -> std::optional<rational_number>;
        friend auto eq(rational_number const& lhs, rational_number const& rhs) -> bool;
        friend auto ne(rational_number const& lhs, rational_number const& rhs) -> bool;
};

#endif // COMP6771_RATIONAL_H