#ifndef COMP6771_MATRIX_H
#define COMP6771_MATRIX_H

#include <memory>
#include <utility>

class matrix {
 public:
	matrix() noexcept = default;

	matrix(std::initializer_list<std::initializer_list<int>> il)
	: n_rows_{static_cast<std::size_t>(std::distance(il.begin(), il.end()))}
	, n_cols_{static_cast<std::size_t>(std::distance(il.begin()->begin(), il.begin()->end()))} {
		data_ = std::make_unique<int[]>(n_rows_ * n_cols_);
		std::size_t row = 0;
		for (auto const& row_list : il) {
			if (row_list.size() != n_cols_) {
				throw std::logic_error("Columns are not equal length");
			}
			std::size_t col = 0;
			for (auto const& val : row_list) {
				data_[row * n_cols_ + col] = val;
				++col;
			}
			++row;
		}
	}

	matrix(const matrix& other) {
		n_rows_ = other.n_rows_;
		n_cols_ = other.n_cols_;
		data_ = std::make_unique<int[]>(n_rows_ * n_cols_);
		for (std::size_t i = 0; i < n_rows_ * n_cols_; ++i) {
			data_[i] = other.data_[i];
		}
	}

	matrix(matrix&& other) {
		n_rows_ = std::exchange(other.n_rows_, 0);
		n_cols_ = std::exchange(other.n_cols_, 0);
		data_ = std::exchange(other.data_, nullptr);
	}

	matrix& operator=(const matrix& other) {
		if (this == &other) {
			return *this;
		}
		n_rows_ = other.n_rows_;
		n_cols_ = other.n_cols_;
		data_ = std::make_unique<int[]>(n_rows_ * n_cols_);
		for (std::size_t i = 0; i < n_rows_ * n_cols_; ++i) {
			data_[i] = other.data_[i];
		}
		return *this;
	}

	matrix& operator=(matrix&& other) noexcept {
		if (this == &other) {
			return *this;
		}
		n_rows_ = std::exchange(other.n_rows_, 0);
		n_cols_ = std::exchange(other.n_cols_, 0);
		data_ = std::exchange(other.data_, nullptr);
		return *this;
	}

	int& operator()(std::size_t r, std::size_t c) {
        if (r >= n_rows_ || c >= n_cols_) {
            throw std::domain_error("(" + std::to_string(r) + ", " + std::to_string(c) + ") does not fit within a matrix with dimensions (" + std::to_string(n_rows_) + ", " + std::to_string(n_cols_) + ")");
        }
        return data_[r * n_cols_ + c];
    }


	const int& operator()(std::size_t r, std::size_t c) const {
        if (r >= n_rows_ || c >= n_cols_) {
            throw std::domain_error("(" + std::to_string(r) + ", " + std::to_string(c) + ") does not fit within a matrix with dimensions (" + std::to_string(n_rows_) + ", " + std::to_string(n_cols_) + ")");
        }
        return data_[r * n_cols_ + c];
    }

    bool operator==(const matrix &rhs) const noexcept {
        if (n_rows_ != rhs.n_rows_ || n_cols_ != rhs.n_cols_) {
            return false;
        }
        for (std::size_t i = 0; i < n_rows_; ++i) {
            for (std::size_t j = 0; j < n_cols_; ++j) {
                if (data_[i * n_cols_ + j] != rhs.data_[i * n_cols_ + j]) {
                    return false;
                }
            }
        }
        return true;
    }

    std::pair<std::size_t, std::size_t> dimensions() const noexcept {
		return {n_rows_, n_cols_};
	}

	const int *data() const noexcept {
		return data_.get();
	}

 private:
	std::size_t n_rows_{};
	std::size_t n_cols_{};
	std::unique_ptr<int[]> data_;
};

#endif // COMP6771_MATRIX_H
