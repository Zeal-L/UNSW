#include <forward_list>
#include <type_traits>
#include <unordered_set>
#include <algorithm>
#include <compare>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <stack>
#include <string>
#include <tuple>
#include <typeindex>
#include <typeinfo>
#include <utility>
#include <vector>
using namespace std;


constexpr auto foo(const auto &f) -> decltype(auto) {
	if constexpr (sizeof(f) != sizeof(void *)) {
		auto val = f;
		return val;
	} else {
		auto val = *f;
		return val;
	}
}

int main() {
	constexpr int arr[3] = {};
	auto var = foo(arr);

	constexpr int arr2[3] = {};
	auto x = arr2;
}


