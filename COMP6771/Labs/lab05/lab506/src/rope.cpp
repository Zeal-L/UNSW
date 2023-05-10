#include "./rope.h"

rope::iter::iter(std::vector<std::string> vec, std::size_t vec_index, std::size_t str_index) noexcept : vec_{vec}, vec_index_{vec_index}, str_index_{str_index} {}

auto rope::iter::operator*() const noexcept -> reference {
    return vec_[vec_index_][str_index_];
}

auto rope::iter::operator->() const noexcept -> pointer {
    return &vec_[vec_index_][str_index_];
}

auto rope::iter::operator++() noexcept -> iter& {
    if (str_index_ < vec_[vec_index_].size() - 1) {
        ++str_index_;
    } else {
        ++vec_index_;
        str_index_ = 0;
    }
    if (vec_index_ == vec_.size()) {
        vec_index_ = vec_.size() - 1;
        str_index_ = vec_[vec_index_].size();
    }
    return *this;
}

auto rope::iter::operator++(int) noexcept -> iter {
    auto tmp = *this;
    ++*this;
    return tmp;
}

auto rope::iter::operator--() noexcept -> iter& {
    if (str_index_ > 0) {
        --str_index_;
    } else {
        --vec_index_;
        str_index_ = vec_[vec_index_].size() - 1;
    }
    return *this;
}

auto rope::iter::operator--(int) noexcept -> iter {
    auto tmp = *this;
    --*this;
    return tmp;
}


auto rope::reverse_iter::operator*() const noexcept -> reference {
    return vec_[vec_index_][str_index_];
}

auto rope::reverse_iter::operator->() const noexcept -> pointer {
    return &vec_[vec_index_][str_index_];
}

auto rope::reverse_iter::operator++() noexcept -> reverse_iter& {
    if (str_index_ < vec_[vec_index_].size() - 1) {
        ++str_index_;
    } else {
        ++vec_index_;
        str_index_ = 0;
    }
    if (vec_index_ == vec_.size()) {
        vec_index_ = vec_.size() - 1;
        str_index_ = vec_[vec_index_].size();
    }
    return *this;
}

auto rope::reverse_iter::operator++(int) noexcept -> reverse_iter {
    auto tmp = *this;
    ++*this;
    return tmp;
}

auto rope::reverse_iter::operator--() noexcept -> reverse_iter& {
    if (str_index_ > 0) {
        --str_index_;
    } else {
        --vec_index_;
        str_index_ = vec_[vec_index_].size() - 1;
    }
    return *this;
}

auto rope::reverse_iter::operator--(int) noexcept -> reverse_iter {
    auto tmp = *this;
    --*this;
    return tmp;
}

auto rope::begin() const noexcept -> iterator {
    return cbegin();
}

auto rope::cbegin() const noexcept -> const_iterator {
    return const_iterator{rope_, 0, 0};
}

auto rope::rbegin() const noexcept -> reverse_iterator {
    return crbegin();
}

auto rope::crbegin() const noexcept -> const_reverse_iterator {
    return const_reverse_iterator(rope_, 0, 0);
}

auto rope::end() const noexcept -> iterator {
    return cend();
}

auto rope::cend() const noexcept -> const_iterator {
    return const_iterator{rope_, rope_.size() - 1, rope_.back().size()};
}

auto rope::rend() const noexcept -> reverse_iterator {
    return crend();
}

auto rope::crend() const noexcept -> const_reverse_iterator {
    return const_reverse_iterator{rope_, rope_.size() - 1, rope_.back().size()};
}

