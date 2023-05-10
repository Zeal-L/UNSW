#ifndef COMP6771_ROPE_H
#define COMP6771_ROPE_H

#include <string>
#include <utility>
#include <vector>
#include <iterator>
#include <algorithm>

class rope {
	class iter {
		friend class rope;

	 public:
		using iterator_category = std::bidirectional_iterator_tag;
		using value_type = const char;
		using reference = const char&;
		using pointer = const char*;
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
			if (lhs.vec_index_ != rhs.vec_index_) {
				return false;
			}
			if (lhs.str_index_ != rhs.str_index_) {
				return false;
			}
			return true;
		}
		friend auto operator!=(const iter& lhs, const iter& rhs) noexcept -> bool {
			return !(lhs == rhs);
		}

	 private:
		std::vector<std::string> vec_{};
		std::size_t vec_index_{};
		std::size_t str_index_{};

		iter(std::vector<std::string> vec, std::size_t vec_index, std::size_t str_index) noexcept;
	};

	class reverse_iter {
		friend class rope;

	 public:
		using iterator_category = std::bidirectional_iterator_tag;
		using value_type = const char;
		using reference = const char&;
		using pointer = const char*;
		using difference_type = std::ptrdiff_t;

		reverse_iter() noexcept = default;
		reverse_iter(const reverse_iter& other) noexcept = default;

		reference operator*() const noexcept;
		pointer operator->() const noexcept;

		auto operator++() noexcept -> reverse_iter&;
		auto operator++(int) noexcept -> reverse_iter;
		auto operator--() noexcept -> reverse_iter&;
		auto operator--(int) noexcept -> reverse_iter;

		friend auto operator==(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			if (lhs.vec_index_ != rhs.vec_index_) {
				return false;
			}
			if (lhs.str_index_ != rhs.str_index_) {
				return false;
			}
			return true;
		}
		friend auto operator!=(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return !(lhs == rhs);
		}

	 private:
		std::vector<std::string> vec_{};
		std::size_t vec_index_{};
		std::size_t str_index_{};

		reverse_iter(std::vector<std::string> vec, std::size_t vec_index, std::size_t str_index) noexcept {
			for (auto i = vec.size(); i > 0; --i) {
				vec_.push_back(vec[i - 1]);
			}
			for (auto i = 0u; i < vec_.size(); ++i) {
				std::reverse(vec_[i].begin(), vec_[i].end());
			}
			vec_index_ = vec_index;
			str_index_ = str_index;
		}
	};

 public:
	using const_iterator = iter;
	using iterator = const_iterator;
	using reverse_iterator = reverse_iter;
	using const_reverse_iterator = reverse_iterator;

	auto begin() const noexcept -> iterator;
	auto cbegin() const noexcept -> const_iterator;

	auto rbegin() const noexcept -> reverse_iterator;
	auto crbegin() const noexcept -> const_reverse_iterator;

	auto end() const noexcept -> iterator;
	auto cend() const noexcept -> const_iterator;

	auto rend() const noexcept -> reverse_iterator;
	auto crend() const noexcept -> const_reverse_iterator;

	rope() = default;

	explicit rope(std::vector<std::string> rope)
	: rope_{std::move(rope)} {}

 private:
	std::vector<std::string> rope_;
};

#endif // COMP6771_ROPE_H