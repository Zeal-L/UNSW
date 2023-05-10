#ifndef COMP6771_ASS2_FSV_H
#define COMP6771_ASS2_FSV_H

#include <compare>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace fsv {
	using filter = std::function<bool(const char&)>;

	class filtered_string_view {
		class iter {
			friend class filtered_string_view;

		 public:
			using iterator_category = std::bidirectional_iterator_tag;
			using value_type = const char;
			using reference = const char&;
			using pointer = void;
			using difference_type = std::ptrdiff_t;

			iter() noexcept = default;
			iter(const iter& other) noexcept = default;

			reference operator*() const noexcept;
			pointer operator->() const noexcept;

			auto operator++() noexcept -> iter&;
			auto operator++(int) noexcept -> iter;
			auto operator--() noexcept -> iter&;
			auto operator--(int) noexcept -> iter;

			friend auto operator==(const iter& lhs, const iter& rhs) noexcept -> bool {
				if (lhs.ptr_ != rhs.ptr_) {
					return false;
				}
				if (lhs.predicate_.target_type() != rhs.predicate_.target_type()) {
					return false;
				}
				return true;
			}
			friend auto operator!=(const iter& lhs, const iter& rhs) noexcept -> bool {
				return !(lhs == rhs);
			}

		 private:
			value_type* ptr_{};
			filter predicate_;
			iter(const char* data, filter predicate) noexcept;
		};

	 public:
		static filter default_predicate;

		//? //////////////////////////////////////////////
		//  Iterator related 				↓↓↓↓↓↓
		//? //////////////////////////////////////////////

		using const_iterator = iter;
		using iterator = const_iterator;
		using reverse_iterator = std::reverse_iterator<iterator>;
		using const_reverse_iterator = std::reverse_iterator<const_iterator>;

		auto begin() const noexcept -> iterator;
		auto cbegin() const noexcept -> const_iterator;

		auto rbegin() const noexcept -> reverse_iterator;
		auto crbegin() const noexcept -> const_reverse_iterator;

		auto end() const noexcept -> iterator;
		auto cend() const noexcept -> const_iterator;

		auto rend() const noexcept -> reverse_iterator;
		auto crend() const noexcept -> const_reverse_iterator;

		//? //////////////////////////////////////////////
		//  Constructors and Destructor  	↓↓↓↓↓↓
		//? //////////////////////////////////////////////

		filtered_string_view() noexcept;
		filtered_string_view(const std::string& str) noexcept;
		filtered_string_view(const std::string& str, filter predicate) noexcept;
		filtered_string_view(const char* str) noexcept;
		filtered_string_view(const char* str, filter predicate) noexcept;
		filtered_string_view(const filtered_string_view& other);
		filtered_string_view(filtered_string_view&& other) noexcept;
		~filtered_string_view() noexcept = default;

		//? //////////////////////////////////////////////
		//  Member Operators				↓↓↓↓↓↓
		//? //////////////////////////////////////////////

		auto operator=(const filtered_string_view& other) -> filtered_string_view&;
		auto operator=(filtered_string_view&& other) noexcept -> filtered_string_view&;
		auto operator[](int n) const noexcept -> const char&;
		explicit operator std::string() const noexcept;

		//? //////////////////////////////////////////////
		//  Member Functions				↓↓↓↓↓↓
		//? //////////////////////////////////////////////

		auto at(int index) const -> const char&;
		auto size() const noexcept -> std::size_t;
		auto empty() const noexcept -> bool;
		auto data() const noexcept -> const char*;
		auto predicate() const noexcept -> const filter&;

	 private:
		const char* data_;
		std::size_t size_;
		filter predicate_;

		auto get_filtered_string() const noexcept -> std::string;
	};

	//? //////////////////////////////////////////////
	//  Non-Member Functions				↓↓↓↓↓↓
	//? //////////////////////////////////////////////

	// Equality Comparison
	auto operator==(const filtered_string_view& lhs, const filtered_string_view& rhs) noexcept -> bool;
	// Relational Comparison
	auto operator<=>(const filtered_string_view& lhs, const filtered_string_view& rhs) noexcept -> std::strong_ordering;
	// Output Stream
	auto operator<<(std::ostream& os, const filtered_string_view& fsv) noexcept -> std::ostream&;

	//? //////////////////////////////////////////////
	//  Non-Member Utility Functions		↓↓↓↓↓↓
	//? //////////////////////////////////////////////

	auto compose(const filtered_string_view& fsv, const std::vector<filter>& filts) noexcept -> filtered_string_view;
	auto split(const filtered_string_view& fsv, const filtered_string_view& tok) noexcept
	    -> std::vector<filtered_string_view>;
	auto substr(const filtered_string_view& fsv, int pos = 0, int count = 0) noexcept -> filtered_string_view;

} // namespace fsv

#endif // COMP6771_ASS2_FSV_H
