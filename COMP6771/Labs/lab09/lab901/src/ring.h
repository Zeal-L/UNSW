#ifndef COMP6771_RING_H
#define COMP6771_RING_H

#include <initializer_list>
#include <iterator>

template<typename T, std::size_t N>
class ring {
 public:
	ring() = default;
	ring(std::initializer_list<T> il)
	: ring(il.begin(), il.end()) {}
	template<typename InputIt>
	ring(InputIt first, InputIt last) {
        size_ = static_cast<std::size_t>(std::distance(first, last));
        if (size_ > N) {
            throw std::invalid_argument("Not enough capacity");
        }

		for (auto it = first; it != last; ++it) {
			elems_[tail_] = *it;
            tail_ = (tail_ + 1) % N;
		}
	}
    ~ring() = default;

    auto push(const T &t) -> void {
        if (size_ + 1 >= N) {
            return;
        }

        elems_[tail_] = t;
        tail_ = (tail_ + 1) % N;
        ++size_;
    }

    auto peek() const -> const T& {
        return elems_[head_];
    }

    auto pop() -> void {
        if (size_ == 0) {
            return;
        }

        head_ = (head_ + 1) % N;
        --size_;
    }

    auto size() const -> std::size_t {
        return size_;
    }

    // auto size() const -> long unsigned int {
    //     return static_cast<long unsigned int>(size_);
    // }

 private:
	T elems_[N]{};
	std::size_t head_{};
	std::size_t tail_{};
	std::size_t size_{};
};

template<typename T, typename... Args>
ring(T, Args...) -> ring<T, sizeof...(Args) + 1>;


#endif // COMP6771_RING_H
