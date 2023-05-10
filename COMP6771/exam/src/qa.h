#ifndef COMP6771_EXAM_QA
#define COMP6771_EXAM_QA

#include <forward_list>
#include <type_traits>
#include <algorithm>
#include <compare>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <list>
#include <memory>
#include <string>
#include <typeindex>
#include <typeinfo>
#include <utility>
#include <vector>

template<typename T>
struct remove_array_ref {
    using type = T;
};

template<typename T>
using remove_array_ref_t = typename remove_array_ref<T>::type;

template<typename T>
struct remove_array_ref<T[]> {
    using type = remove_array_ref_t<T>;
};

template<typename T, std::size_t N>
struct remove_array_ref<T[N]> {
    using type = remove_array_ref_t<T>;
};

template<typename T>
struct remove_array_ref<T&> {
    using type = remove_array_ref_t<T>;
};

template<typename T>
struct remove_array_ref<T&&> {
    using type = remove_array_ref_t<T>;
};

template<typename T, typename N>
class maybe {
 public:
	using value_type = remove_array_ref_t<T>;
	using reference = value_type&;
	using pointer = std::conditional_t<std::is_class_v<value_type>, value_type*, void>;

	maybe() noexcept {
		val_ = N::null();
	}
	explicit maybe(const value_type& arg) noexcept {
		if constexpr (std::is_convertible_v<decltype(arg), const value_type&>) {
			val_ = std::move(arg);
		}
		else {
			val_ = N::null();
		}
	}
	template<typename... Args>
	explicit maybe(Args&&... args) {
		try {
			val_ = N::ctor(std::forward<Args>(args)...);
		} catch (...) {
			throw std::runtime_error{"cannot complete construction"};
		}
	}
	maybe(const maybe& other) = delete;
	maybe(maybe&& other) noexcept {
		if (this != &other) {
			val_ = other.val_;
			other.val_ = N::null();
		}
	}
	~maybe() noexcept {
		if (val_ != N::null()) {
			N::dtor(val_);
		}
	}

	auto operator=(const maybe& other) -> maybe& = delete;
	auto operator=(maybe&& other) noexcept -> maybe& {
		if (this != &other) {
			if (val_ != N::null()) {
				N::dtor(val_);
			}
			val_ = other.val_;
			other.val_ = N::null();
		}
		return *this;
	}

	operator bool() const noexcept {
		return val_ != N::null();
	}

	auto operator*() -> reference {
		if (val_ == N::null()) {
			throw std::runtime_error{"operator*::bad access"};
		}
		return val_;
	}

	auto operator->() -> pointer {
		if (val_ == N::null()) {
			throw std::runtime_error{"operator->::bad access"};
		}
		return &val_;
	}

	auto operator==(const maybe& other) const noexcept -> bool {
		if (val_ == N::null() && other.val_ == N::null()) {
			return true;
		}
		if (val_ == N::null() || other.val_ == N::null()) {
			return false;
		}
		return val_ == other.val_;
	}

 private:
	value_type val_;
};

#endif // COMP6771_EXAM_QA
