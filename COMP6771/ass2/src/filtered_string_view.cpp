#include "./filtered_string_view.h"

#include <cstring>
#include <stdexcept>
#include <utility>

using namespace fsv;

filter filtered_string_view::default_predicate = [](const char&) { return true; };

//? //////////////////////////////////////////////
//  Constructors and Destructor  	↓↓↓↓↓↓
//? //////////////////////////////////////////////

filtered_string_view::filtered_string_view() noexcept
: data_{nullptr}
, size_{0}
, predicate_{default_predicate} {}

filtered_string_view::filtered_string_view(const std::string& str) noexcept
: data_{str.data()}
, size_{str.size()}
, predicate_{default_predicate} {}

filtered_string_view::filtered_string_view(const std::string& str, filter predicate) noexcept
: data_{str.data()}
, size_{str.size()}
, predicate_{std::move(predicate)} {}

filtered_string_view::filtered_string_view(const char* str) noexcept
: data_{str}
, size_{std::strlen(str)}
, predicate_{default_predicate} {}

filtered_string_view::filtered_string_view(const char* str, filter predicate) noexcept
: data_{str}
, size_{std::strlen(str)}
, predicate_{std::move(predicate)} {}

// Copy constructor
filtered_string_view::filtered_string_view(const filtered_string_view& other)
: data_{other.data_}
, size_{other.size_}
, predicate_{other.predicate_} {}

// Move constructor
filtered_string_view::filtered_string_view(filtered_string_view&& other) noexcept
: data_{std::exchange(other.data_, nullptr)}
, size_{std::exchange(other.size_, 0)}
, predicate_{std::exchange(other.predicate_, default_predicate)} {}

//? //////////////////////////////////////////////
//  Member Operators				↓↓↓↓↓↓
//? //////////////////////////////////////////////

// Copy assignment operator
auto filtered_string_view::operator=(const filtered_string_view& other) -> filtered_string_view& {
	data_ = other.data_;
	size_ = other.size_;
	predicate_ = other.predicate_;
	return *this;
}

// Move assignment operator
auto filtered_string_view::operator=(filtered_string_view&& other) noexcept -> filtered_string_view& {
	data_ = std::exchange(other.data_, nullptr);
	size_ = std::exchange(other.size_, 0);
	predicate_ = std::exchange(other.predicate_, default_predicate);
	return *this;
}

// Subscript operator
auto filtered_string_view::operator[](int n) const noexcept -> const char& {
	auto temp = n;
	for (auto i = 0u; i < size_; ++i) {
		if (predicate_(data_[i])) {
			if (temp == 0) {
				return data_[i];
			}
			--temp;
		}
	}
	return data_[size_];
}

// String Type Conversion
filtered_string_view::operator std::string() const noexcept {
	return get_filtered_string();
}

//? //////////////////////////////////////////////
//  Member Functions				↓↓↓↓↓↓
//? //////////////////////////////////////////////

// Member Functions - at
auto filtered_string_view::at(int index) const -> const char& {
	auto temp = index;
	for (auto i = 0u; i < size_; ++i) {
		if (predicate_(data_[i])) {
			if (temp == 0) {
				return data_[i];
			}
			--temp;
		}
	}
	std::string error_message = "filtered_string_view::at(" + std::to_string(index) + "): invalid index";
	throw std::domain_error(error_message);
}

// Member Functions - size
auto filtered_string_view::size() const noexcept -> std::size_t {
	return get_filtered_string().size();
}

// Member Functions - empty
auto filtered_string_view::empty() const noexcept -> bool {
	return get_filtered_string().empty();
}

// Member Functions - data
auto filtered_string_view::data() const noexcept -> const char* {
	return data_;
}

// Member Functions - predicate
auto filtered_string_view::predicate() const noexcept -> const filter& {
	return predicate_;
}

//? //////////////////////////////////////////////
//  Iterator related 				↓↓↓↓↓↓
//? //////////////////////////////////////////////

filtered_string_view::iter::reference filtered_string_view::iter::operator*() const noexcept {
	return *ptr_;
}

filtered_string_view::iter::pointer filtered_string_view::iter::operator->() const noexcept {}

auto filtered_string_view::iter::operator++() noexcept -> filtered_string_view::iter& {
	do {
		++ptr_;
	} while (!predicate_(*ptr_) && *ptr_ != '\0');
	return *this;
}

auto filtered_string_view::iter::operator++(int) noexcept -> filtered_string_view::iter {
	auto tmp = *this;
	do {
		++ptr_;
	} while (!predicate_(*ptr_) && *ptr_ != '\0');
	return tmp;
}

auto filtered_string_view::iter::operator--() noexcept -> filtered_string_view::iter& {
	do {
		--ptr_;
	} while (!predicate_(*ptr_) && *ptr_ != '\0');
	return *this;
}

auto filtered_string_view::iter::operator--(int) noexcept -> filtered_string_view::iter {
	auto tmp = *this;
	do {
		--ptr_;
	} while (!predicate_(*ptr_) && *ptr_ != '\0');
	return tmp;
}

filtered_string_view::iter::iter(const char* data, filter predicate) noexcept
: ptr_{data}
, predicate_{predicate} {}

auto filtered_string_view::begin() const noexcept -> filtered_string_view::iterator {
	return cbegin();
}

auto filtered_string_view::cbegin() const noexcept -> filtered_string_view::const_iterator {
	const char* ptr_ = data_;
	while (!predicate_(*ptr_) && *ptr_ != '\0') {
		++ptr_;
	}
	return const_iterator{ptr_, predicate_};
}

auto filtered_string_view::rbegin() const noexcept -> filtered_string_view::reverse_iterator {
	return crbegin();
}

auto filtered_string_view::crbegin() const noexcept -> filtered_string_view::const_reverse_iterator {
	return const_reverse_iterator{cend()};
}

auto filtered_string_view::end() const noexcept -> filtered_string_view::iterator {
	return cend();
}

auto filtered_string_view::cend() const noexcept -> filtered_string_view::const_iterator {
	return const_iterator{data_ + size_, predicate_};
}

auto filtered_string_view::rend() const noexcept -> filtered_string_view::reverse_iterator {
	return crend();
}

auto filtered_string_view::crend() const noexcept -> filtered_string_view::const_reverse_iterator {
	return const_reverse_iterator{cbegin()};
}

auto filtered_string_view::get_filtered_string() const noexcept -> std::string {
	auto filtered = std::string{};
	for (auto i = 0u; i < size_; ++i) {
		if (predicate_(data_[i])) {
			filtered.push_back(data_[i]);
		}
	}
	return filtered;
}

//? //////////////////////////////////////////////
//  Non-Member Functions				↓↓↓↓↓↓
//? //////////////////////////////////////////////

// Equality Comparison
auto fsv::operator==(const filtered_string_view& lhs, const filtered_string_view& rhs) noexcept -> bool {
	return static_cast<std::string>(lhs) == static_cast<std::string>(rhs);
}
// Relational Comparison
auto fsv::operator<=>(const filtered_string_view& lhs, const filtered_string_view& rhs) noexcept -> std::strong_ordering {
	return static_cast<std::string>(lhs) <=> static_cast<std::string>(rhs);
}
// Output Stream
auto fsv::operator<<(std::ostream& os, const filtered_string_view& fsv) noexcept -> std::ostream& {
	os << static_cast<std::string>(fsv);
	return os;
}

//? //////////////////////////////////////////////
//  Non-Member Utility Functions		↓↓↓↓↓↓
//? //////////////////////////////////////////////

auto fsv::compose(const filtered_string_view& fsv, const std::vector<filter>& filts) noexcept -> filtered_string_view {
	filter new_predicate = fsv.predicate();
	for (auto const& filt : filts) {
		new_predicate = [new_predicate, filt](const char& c) { return new_predicate(c) && filt(c); };
	}

	return filtered_string_view{fsv.data(), new_predicate};
}

namespace {
	auto
	split_filter(const filter f, const std::size_t reset_size, const std::size_t start, const std::size_t end) noexcept
	    -> filter {
		auto curr = std::size_t{0};
		return [f, reset_size, start, end, curr](const char& c) mutable {
			bool result = false;
			if (end != std::string::npos && f(c) && (curr >= start && curr <= end)) {
				result = true;
			}
			++curr;
			if (curr == reset_size) {
				curr = 0;
			}
			return result;
		};
	}
} // namespace

auto fsv::split(const filtered_string_view& fsv, const filtered_string_view& tok) noexcept
    -> std::vector<filtered_string_view> {
	auto result = std::vector<filtered_string_view>{};
	auto fsv_str = std::string{fsv.data()};
	auto tok_str = std::string{tok.data()};
	if (tok_str.empty()) {
		result.emplace_back(fsv);
		return result;
	}

	auto reset_size = fsv_str.size();
	auto old_pos = std::size_t{0};
	auto pos = fsv_str.find(tok_str);

	while (pos != std::string::npos) {
		result.emplace_back(fsv.data(), split_filter(fsv.predicate(), reset_size, old_pos, pos - 1));
		old_pos = pos + tok_str.size();
		pos = fsv_str.find(tok_str, old_pos);
	}
	result.emplace_back(fsv.data(), split_filter(fsv.predicate(), reset_size, old_pos, fsv_str.size()));
	return result;
}

auto fsv::substr(const filtered_string_view& fsv, int pos, int count) noexcept -> filtered_string_view {
	auto fsv_str_size = std::string{fsv.data()}.size();
	auto rcount = count <= 0 ? static_cast<int>(fsv_str_size) - pos : count;
	auto old_predicate = fsv.predicate();
	auto fn_curr = std::size_t{0};
	auto fn_curr_rcount = std::size_t{0};

	auto offset = 0;
	for (auto i = 0u; i < fsv_str_size; ++i) {
		if (old_predicate(fsv.data()[i])) {
			break;
		}
		++offset;
	}

	filter new_predicate = [old_predicate,
	                        fn_curr,
	                        fn_start = static_cast<std::size_t>(pos + offset),
	                        fn_end = fsv_str_size,
	                        rcount = static_cast<std::size_t>(rcount),
	                        fn_curr_rcount](const char& c) mutable {
		bool result = false;
		if (fn_curr >= fn_start && fn_curr <= fn_end && fn_curr_rcount < rcount && old_predicate(c)) {
			result = true;
			++fn_curr_rcount;
		}
		++fn_curr;
		if (fn_curr == fn_end) {
			fn_curr = 0;
			fn_curr_rcount = 0;
		}
		return result;
	};

	return filtered_string_view{fsv.data(), new_predicate};
}
