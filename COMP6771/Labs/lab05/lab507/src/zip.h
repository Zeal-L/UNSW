#ifndef COMP6771_ZIP_H
#define COMP6771_ZIP_H

#include <algorithm>
#include <compare>
#include <iterator>
#include <vector>

using ivec = std::vector<int>;
using ipair = std::pair<int, int>;

class zip {
	class iter {
		friend class zip;

	 public:
		using iterator_category = std::random_access_iterator_tag;
		using value_type = const ipair;
		using reference = const ipair&;
		using pointer = const ipair*;
		using difference_type = std::ptrdiff_t;

		iter() noexcept = default;
		iter(const iter& other) noexcept = default;

		reference operator*() const noexcept {
			return vec_[index_];
		}

		pointer operator->() const noexcept {
			return &vec_[index_];
		}

		auto operator++() noexcept -> iter& {
			++index_;
			return *this;
		}

		auto operator++(int) noexcept -> iter {
			auto temp = *this;
			++index_;
			return temp;
		}

		auto operator--() noexcept -> iter& {
			--index_;
			return *this;
		}

		auto operator--(int) noexcept -> iter {
			auto temp = *this;
			--index_;
			return temp;
		}

		auto operator+(difference_type n) const noexcept -> iter {
			auto temp = *this;
			temp += n;
			return temp;
		}

		friend auto operator+(difference_type n, const iter& rhs) noexcept -> iter {
			return rhs + n;
		}

		auto operator+=(difference_type n) noexcept -> iter& {
			index_ += static_cast<std::size_t>(n);
			return *this;
		}

		auto operator-(difference_type n) const noexcept -> iter {
			auto temp = *this;
			temp -= n;
			return temp;
		}

		auto operator-(const iter& rhs) const noexcept -> difference_type {
			return static_cast<long long int>(index_ - rhs.index_);
		}

		auto operator-=(difference_type n) noexcept -> iter& {
			index_ -= static_cast<std::size_t>(n);
			return *this;
		}

		auto operator[](difference_type n) const noexcept -> reference {
			return *(*this + n);
		}

		friend auto operator==(const iter& lhs, const iter& rhs) noexcept -> bool {
			return lhs.index_ == rhs.index_;
		}

		friend auto operator!=(const iter& lhs, const iter& rhs) noexcept -> bool {
			return !(lhs == rhs);
		}

		friend auto operator<(const iter& lhs, const iter& rhs) noexcept -> bool {
			return lhs.index_ < rhs.index_;
		}

		friend auto operator>(const iter& lhs, const iter& rhs) noexcept -> bool {
			return rhs < lhs;
		}

		friend auto operator<=(const iter& lhs, const iter& rhs) noexcept -> bool {
			return !(lhs > rhs);
		}

		friend auto operator>=(const iter& lhs, const iter& rhs) noexcept -> bool {
			return !(lhs < rhs);
		}

	 private:
        std::vector<ipair> vec_ {};
		std::size_t index_{};
		iter(const ivec v1, const ivec v2, const std::size_t index) noexcept : index_{index} {
            for (auto i = 0u; i < std::min(v1.size(), v2.size()); ++i) {
                vec_.push_back(std::make_pair(v1[i], v2[i]));
            }
        };
	};

    class reverse_iter {
		friend class zip;

	 public:
		using iterator_category = std::random_access_iterator_tag;
		using value_type = const ipair;
		using reference = const ipair&;
		using pointer = const ipair*;
		using difference_type = std::ptrdiff_t;

		reverse_iter() noexcept = default;
		reverse_iter(const reverse_iter& other) noexcept = default;

		reference operator*() const noexcept {
			return vec_[index_];
		}

		pointer operator->() const noexcept {
			return &vec_[index_];
		}

		auto operator++() noexcept -> reverse_iter& {
			++index_;
			return *this;
		}

		auto operator++(int) noexcept -> reverse_iter {
			auto temp = *this;
			++index_;
			return temp;
		}

		auto operator--() noexcept -> reverse_iter& {
			--index_;
			return *this;
		}

		auto operator--(int) noexcept -> reverse_iter {
			auto temp = *this;
			--index_;
			return temp;
		}

		auto operator+(difference_type n) const noexcept -> reverse_iter {
			auto temp = *this;
			temp += n;
			return temp;
		}

		friend auto operator+(difference_type n, const reverse_iter& rhs) noexcept -> reverse_iter {
			return rhs + n;
		}

		auto operator+=(difference_type n) noexcept -> reverse_iter& {
			index_ += static_cast<std::size_t>(n);
			return *this;
		}

		auto operator-(difference_type n) const noexcept -> reverse_iter {
			auto temp = *this;
			temp -= n;
			return temp;
		}

		auto operator-(const reverse_iter& rhs) const noexcept -> difference_type {
			return static_cast<long long int>(index_ - rhs.index_);
		}

		auto operator-=(difference_type n) noexcept -> reverse_iter& {
			index_ -= static_cast<std::size_t>(n);
			return *this;
		}

		auto operator[](difference_type n) const noexcept -> reference {
			return *(*this + n);
		}

		friend auto operator==(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return lhs.index_ == rhs.index_;
		}

		friend auto operator!=(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return !(lhs == rhs);
		}

		friend auto operator<(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return lhs.index_ < rhs.index_;
		}

		friend auto operator>(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return rhs < lhs;
		}

		friend auto operator<=(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return !(lhs > rhs);
		}

		friend auto operator>=(const reverse_iter& lhs, const reverse_iter& rhs) noexcept -> bool {
			return !(lhs < rhs);
		}

	 private:
        std::vector<ipair> vec_ {};
		std::size_t index_{};
		reverse_iter(const ivec v1, const ivec v2, const std::size_t index) noexcept : index_{index} {
            for (auto i = std::min(v1.size(), v2.size()); i > 0; --i) {
                vec_.push_back(std::make_pair(v1[i - 1], v2[i - 1]));
            }
        };
	};

 public:
	using const_iterator = iter;
	using iterator = const_iterator;
	using reverse_iterator = reverse_iter;
	using const_reverse_iterator = reverse_iterator;

	auto begin() const noexcept -> iterator {
        return cbegin();
    }
	auto cbegin() const noexcept -> const_iterator {
        return const_iterator(i1_, i2_, 0);
    }

	auto rbegin() const noexcept -> reverse_iterator {
        return crbegin();
    }
	auto crbegin() const noexcept -> const_reverse_iterator {
        return reverse_iterator(i1_, i2_, 0);
    }

	auto end() const noexcept -> iterator {
        return cend();
    }
	auto cend() const noexcept -> const_iterator {
        return const_iterator(i1_, i2_, std::min(i1_.size(), i2_.size()));
    }

	auto rend() const noexcept -> reverse_iterator {
        return crend();
    }
	auto crend() const noexcept -> const_reverse_iterator {
        return reverse_iterator(i1_, i2_, std::min(i1_.size(), i2_.size()));
    }

	zip() = default;
	zip(const ivec& rng1, const ivec& rng2)
	: i1_{rng1}
	, i2_{rng2} {};

 private:
	ivec i1_;
	ivec i2_;
};

#endif // COMP6771_ZIP_H
