#include "./rope.h"

#include <iostream>
#include <iterator>


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

static_assert(std::bidirectional_iterator<rope::iterator>);
static_assert(std::bidirectional_iterator<rope::const_iterator>);
static_assert(reversible_container<rope>);

int main() {
	auto r = rope{{"rbg", "gsc", "rse"}};
	const auto cr = rope{{"dppt", "b2w2", "xysm"}};

	for (auto it = r.begin(); it != r.end(); ++it) {
		std::cout << *it;
	}
	std::cout << std::endl;

	for (auto it = cr.begin(); it != cr.end(); ++it) {
		std::cout << *it;
	}
	std::cout << std::endl;

	for (auto it = r.cbegin(); it != r.cend(); ++it) {
		std::cout << *it;
	}
	std::cout << std::endl;

	for (auto it = r.rbegin(); it != r.rend(); ++it) {
		std::cout << *it;
	}
	std::cout << std::endl;

	for (auto it = cr.rbegin(); it != cr.rend(); ++it) {
		std::cout << *it;
	}
	std::cout << std::endl;

	for (auto it = r.crbegin(); it != r.crend(); ++it) {
		std::cout << *it;
	}
	std::cout << std::endl;
}

/* Output should be
rbggscrse
dpptb2w2xysm
rbggscrse
esrcsggbr
msyx2w2btppd
esrcsggbr
*/
