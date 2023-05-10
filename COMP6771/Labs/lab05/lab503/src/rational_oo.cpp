#include "./rational_oo.h"

std::optional<rational_number> rational_number::null;

auto rational_number::operator+(const rational_number& other) const -> rational_number {
	auto ad = (*this).numerator_ * other.denominator_;
	auto bc = (*this).denominator_ * other.numerator_;
	auto bd = (*this).denominator_ * other.denominator_;

	return rational_number(ad + bc, bd);
}

auto rational_number::operator-(const rational_number& other) const -> rational_number {
	auto ad = (*this).numerator_ * other.denominator_;
	auto bc = (*this).denominator_ * other.numerator_;
	auto bd = (*this).denominator_ * other.denominator_;

	return rational_number(ad - bc, bd);
}

auto rational_number::operator*(const rational_number& other) const -> rational_number {
	auto ac = (*this).numerator_ * other.numerator_;
	auto bd = (*this).denominator_ * other.denominator_;

	return rational_number(ac, bd);
}

auto rational_number::operator/(const rational_number& other) const -> std::optional<rational_number> {
	auto ad = (*this).numerator_ * other.denominator_;
	auto bc = (*this).denominator_ * other.numerator_;

	return make_rational(ad, bc);
}

auto rational_number::operator==(const rational_number& other) const -> bool {
	return (*this).numerator_ == other.numerator_ && (*this).denominator_ == other.denominator_;
}

auto rational_number::operator!=(const rational_number& other) const -> bool {
	return !(*this == other);
}

rational_number::operator double() const {
	return static_cast<double>((*this).numerator_) / (*this).denominator_;
}

auto rational_number::operator[](char c) const -> int {
	if (c == '^') {
		return (*this).numerator_;
	}
	else {
		return (*this).denominator_;
	}
}

auto rational_number::operator[](char c) -> int& {
	if (c == '^') {
		return (*this).numerator_;
	}
	else {
		return (*this).denominator_;
	}
}