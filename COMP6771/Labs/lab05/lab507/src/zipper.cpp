#include "./zip.h"

#include <iostream>

template <typename Container>
concept reversible_container = requires(Container c) {
	{c.begin()} -> std::same_as<typename Container::iterator>;
	{c.end()} -> std::same_as<typename Container::iterator>;
	{static_cast<const Container>(c).begin()} -> std::same_as<typename Container::const_iterator>;
	{static_cast<const Container>(c).end()} -> std::same_as<typename Container::const_iterator>;
	{c.cbegin()} -> std::same_as<typename Container::const_iterator>;
	{c.cend()} -> std::same_as<typename Container::const_iterator>;

	{c.rbegin()} -> std::same_as<typename Container::reverse_iterator>;
	{c.rend()} -> std::same_as<typename Container::reverse_iterator>;
	{static_cast<const Container>(c).rbegin()} -> std::same_as<typename Container::const_reverse_iterator>;
	{static_cast<const Container>(c).rend()} -> std::same_as<typename Container::const_reverse_iterator>;
	{c.crbegin()} -> std::same_as<typename Container::const_reverse_iterator>;
	{c.crend()} -> std::same_as<typename Container::const_reverse_iterator>;
};

static_assert(std::random_access_iterator<zip::iterator>);
static_assert(std::random_access_iterator<zip::const_iterator>);
static_assert(reversible_container<zip>);

int main() {
    std::vector<int> i1 = {1, 2, 3};
    std::vector<int> i2 = {4, 5};

	auto zp = zip{i1, i2};

	auto zb = zp.begin();
	auto ze = zp.end();

	std::cout << std::boolalpha << (zb < ze) << std::endl;
	std::cout << std::boolalpha << (zb + 2 == ze) << std::endl;
	std::cout << std::noboolalpha << (ze - zb) << std::endl;

    for (const std::pair<int, int> &p : zp) {
        std::cout << p.first << " " << p.second << std::endl;
    }

	for (auto it = zp.crbegin(), last = zp.crend(); it != last; ++it) {
        std::cout << (*it).first << " " << (*it).second << std::endl;
	}
}

/* Output
true
true
2
1 4
2 5
2 5
1 4
*/
