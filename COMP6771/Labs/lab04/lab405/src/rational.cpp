#include "./rational.h"

std::optional<rational_number> rational_number::null {};

auto rational_number::make_rational(int num, int denom) -> std::optional<rational_number> {
    if (denom == 0) {
        return rational_number::null;
    }
    return rational_number(num, denom);
}

auto rational_number::value() const -> double {
    return static_cast<double>(numerator_) / denominator_;
}

auto add(rational_number const& lhs, rational_number const& rhs) -> rational_number {
    return rational_number(lhs.numerator_ * rhs.denominator_ + rhs.numerator_ * lhs.denominator_,
                           lhs.denominator_ * rhs.denominator_);
}

auto sub(rational_number const& lhs, rational_number const& rhs) -> rational_number  {
    return rational_number(lhs.numerator_ * rhs.denominator_ - rhs.numerator_ * lhs.denominator_,
                           lhs.denominator_ * rhs.denominator_);
}

auto mul(rational_number const& lhs, rational_number const& rhs) -> rational_number {
    return rational_number(lhs.numerator_ * rhs.numerator_, lhs.denominator_ * rhs.denominator_);
}

auto div(rational_number const& lhs, rational_number const& rhs) -> std::optional<rational_number> {
    if (rhs.numerator_ == 0) {
        return rational_number::null;
    }
    return rational_number(lhs.numerator_ * rhs.denominator_, lhs.denominator_ * rhs.numerator_);
}

auto eq(rational_number const& lhs, rational_number const& rhs) -> bool {
    return lhs.numerator_ * rhs.denominator_ == rhs.numerator_ * lhs.denominator_;
}

auto ne(rational_number const& lhs, rational_number const& rhs) -> bool {
    return lhs.numerator_ * rhs.denominator_ != rhs.numerator_ * lhs.denominator_;
}