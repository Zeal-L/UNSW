#include "./pipeline.h"

#include <catch2/catch.hpp>

#include <fstream>
#include <iostream>
#include <sstream>

// dot -T svg client.dot -o client.svg
// dot -T png client.dot -o client.png

template<typename T, T from, T to>
    requires std::is_arithmetic_v<T>
struct source_produce_num : ppl::source<T> {
	T current_value;

	source_produce_num()
	: current_value(from) {}

	auto name() const -> std::string override {
		return std::string("Source - produce ") + typeid(T).name() + ": " + std::to_string(from) + " to "
		       + std::to_string(to);
	}

	auto poll_next() -> ppl::poll override {
		if (from < to) {
			if (current_value > to)
				return ppl::poll::closed;
			++current_value;
			return ppl::poll::ready;
		}
		else if (from > to) {
			if (current_value < to)
				return ppl::poll::closed;
			--current_value;
			return ppl::poll::ready;
		}
		else {
			return ppl::poll::closed;
		}
	}

	auto value() const -> const T& override {
		return current_value;
	}
};

template<typename T>
concept printable = requires(std::ostream& os, const T& t) { os << t; };

template<typename T>
    requires printable<T>
struct sink_print : ppl::sink<T> {
	const ppl::producer<T>* slot0 = nullptr;

	sink_print() = default;

	auto name() const -> std::string override {
		return "Sink - print";
	}

	void connect(const ppl::node* src, int slot) override {
		if (slot == 0) {
			slot0 = static_cast<const ppl::producer<T>*>(src);
		}
	}

	auto poll_next() -> ppl::poll override {
		std::cout << slot0->value() << '\n';
		return ppl::poll::ready;
	}
};

template<typename T, typename U, typename O>
    requires std::is_arithmetic_v<T> && std::is_arithmetic_v<U> && std::is_arithmetic_v<O>
struct component_add : ppl::component<std::tuple<T, U>, O> {
	const ppl::producer<T>* slot0 = nullptr;
	const ppl::producer<U>* slot1 = nullptr;

	mutable O result{};

	component_add() = default;

	auto name() const -> std::string override {
		return std::string("Component - add ") + typeid(T).name() + " " + typeid(U).name();
	}

	void connect(const ppl::node* src, int slot) override {
		if (slot == 0) {
			slot0 = static_cast<const ppl::producer<T>*>(src);
		}
		else if (slot == 1) {
			slot1 = static_cast<const ppl::producer<U>*>(src);
		}
	}

	auto poll_next() -> ppl::poll override {
		return ppl::poll::ready;
	}

	auto value() const -> const O& override {
		result = static_cast<const O&>(slot0->value()) + static_cast<const O&>(slot1->value());
		return result;
	}
};

template<typename T, typename U, typename O>
    requires std::is_arithmetic_v<T> && std::is_arithmetic_v<U> && std::is_arithmetic_v<O>
struct component_add_but_skip_odd : ppl::component<std::tuple<T, U>, O> {
	const ppl::producer<T>* slot0 = nullptr;
	const ppl::producer<U>* slot1 = nullptr;

	mutable O result{};

	component_add_but_skip_odd() = default;

	auto name() const -> std::string override {
		return std::string("Component - add but skip odd ") + typeid(T).name() + " " + typeid(U).name();
	}

	void connect(const ppl::node* src, int slot) override {
		if (slot == 0) {
			slot0 = static_cast<const ppl::producer<T>*>(src);
		}
		else if (slot == 1) {
			slot1 = static_cast<const ppl::producer<U>*>(src);
		}
	}

	auto poll_next() -> ppl::poll override {
		if (slot0->value() % 2 == 0 && slot1->value() % 2 == 0) {
			return ppl::poll::ready;
		}
		else {
			return ppl::poll::empty;
		}
	}

	auto value() const -> const O& override {
		result = static_cast<const O&>(slot0->value()) + static_cast<const O&>(slot1->value());
		return result;
	}
};

template<typename T>
    requires std::is_arithmetic_v<T>
struct component_double_it : ppl::component<std::tuple<T>, T> {
	const ppl::producer<T>* slot0 = nullptr;

	component_double_it() = default;

	mutable T result{};

	auto name() const -> std::string override {
		return std::string("Component - double it ") + typeid(T).name();
	}

	void connect(const ppl::node* src, int slot) override {
		if (slot == 0) {
			slot0 = static_cast<const ppl::producer<T>*>(src);
		}
	}

	auto poll_next() -> ppl::poll override {
		return ppl::poll::ready;
	}

	auto value() const -> const T& override {
		result = slot0->value() * 2;
		return result;
	}
};

template<typename T>
    requires std::is_arithmetic_v<T>
struct component_double_it_but_skip_odd : ppl::component<std::tuple<T>, T> {
	const ppl::producer<T>* slot0 = nullptr;

	component_double_it_but_skip_odd() = default;

	mutable T result{};

	auto name() const -> std::string override {
		return std::string("Component - double it but skip odd ") + typeid(T).name();
	}

	void connect(const ppl::node* src, int slot) override {
		if (slot == 0) {
			slot0 = static_cast<const ppl::producer<T>*>(src);
		}
	}

	auto poll_next() -> ppl::poll override {
		if (slot0->value() % 2 == 0) {
			return ppl::poll::ready;
		}
		else {
			return ppl::poll::empty;
		}
	}

	auto value() const -> const T& override {
		result = slot0->value() * 2;
		return result;
	}
};

// ########################################
// 	pipeline construction and operators
// ########################################

TEST_CASE("Move Constructor") {
	std::string line;
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);
	pip.step();
	pip.step();
	auto pip2 = std::move(pip);
	CHECK(pip.get_node(source) == nullptr);
	CHECK(pip2.get_node(source) != nullptr);
	pip2.run();

	int count = 0;
	while (std::getline(buffer, line)) {
		CHECK(line == std::to_string(++count));
	}

	std::cout.rdbuf(old);
}

TEST_CASE("Move Assignment") {
	std::string line;
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);
	pip.step();
	pip.step();
	ppl::pipeline pip2{};
	pip2 = std::move(pip);
	pip2.run();

	int count = 0;
	while (std::getline(buffer, line)) {
		CHECK(line == std::to_string(++count));
	}

	std::cout.rdbuf(old);
}

// ########################################
// 		Node Management
// ########################################

TEST_CASE("create_node & get_node") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	CHECK(pip.get_node(source)->name() == "Source - produce i: 0 to 10");
}

TEST_CASE("get_node - invalid node") {
	auto pip = ppl::pipeline{};
	CHECK(pip.get_node(0) == nullptr);
}

TEST_CASE("get_node - invalid node - const") {
	const auto pip = ppl::pipeline{};
	CHECK(pip.get_node(0) == nullptr);
}

TEST_CASE("erase_node - single node") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	pip.erase_node(source);
	CHECK(pip.get_node(source) == nullptr);
}

TEST_CASE("erase_node - multiple nodes with connections") {
	auto pip = ppl::pipeline{};
	const auto source_a = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto source_b = pip.create_node<source_produce_num<int, 10, 0>>();
	const auto component = pip.create_node<component_add<int, int, int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source_a, component, 0);
	pip.connect(source_b, component, 1);
	pip.connect(component, sink, 0);

	CHECK_FALSE(pip.get_node(component) == nullptr);
	CHECK_FALSE(pip.get_dependencies(source_a).empty());
	CHECK_FALSE(pip.get_dependencies(source_b).empty());

	pip.erase_node(component);

	CHECK(pip.get_node(component) == nullptr);
	CHECK(pip.get_dependencies(source_a).empty());
	CHECK(pip.get_dependencies(source_b).empty());
}

TEST_CASE("erase_node - invalid node ID") {
	auto pip = ppl::pipeline{};
	pip.create_node<source_produce_num<int, 0, 10>>();

	CHECK_THROWS_MATCHES(pip.erase_node(9), ppl::pipeline_error, Catch::Matchers::Message("invalid node ID"));
}

TEST_CASE("erase_node - node is no longer a valid handle after it is erased") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	pip.erase_node(source);
	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();

	CHECK(source != source2);
	CHECK(source2 == 2);
}

// ########################################
// 		Connection Management
// ########################################

TEST_CASE("connect - successful connection") {
	auto pip = ppl::pipeline{};
	const auto source_a = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto source_b = pip.create_node<source_produce_num<int, 10, 0>>();
	const auto component = pip.create_node<component_add<int, int, int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source_a, component, 0);
	pip.connect(source_b, component, 1);
	pip.connect(component, sink, 0);

	auto res = pip.get_dependencies(source_a);
	CHECK(res.size() == 1);
	CHECK(res[0] == std::make_pair(component, 0));

	auto res2 = pip.get_dependencies(source_b);
	CHECK(res2.size() == 1);
	CHECK(res2[0] == std::make_pair(component, 1));

	auto res3 = pip.get_dependencies(component);
	CHECK(res3.size() == 1);
	CHECK(res3[0] == std::make_pair(sink, 0));
}

TEST_CASE("connect - pipeline_error - invalid_node_id") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	CHECK_THROWS_MATCHES(pip.connect(9, sink, 0), ppl::pipeline_error, Catch::Matchers::Message("invalid node ID"));
	CHECK_THROWS_MATCHES(pip.connect(source, 9, 0), ppl::pipeline_error, Catch::Matchers::Message("invalid node ID"));
}

TEST_CASE("connect - pipeline_error - slot_already_used") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();
	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();

	pip.connect(source, sink, 0);

	CHECK_THROWS_MATCHES(pip.connect(source2, sink, 0),
	                     ppl::pipeline_error,
	                     Catch::Matchers::Message("slot already used"));
}

TEST_CASE("connect - pipeline_error - connection_type_mismatch") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<double>>();

	CHECK_THROWS_MATCHES(pip.connect(source, sink, 0),
	                     ppl::pipeline_error,
	                     Catch::Matchers::Message("connection type mismatch"));
}

TEST_CASE("connect - pipeline_error - no_such_slot") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<double>>();

	CHECK_THROWS_MATCHES(pip.connect(source, sink, 1), ppl::pipeline_error, Catch::Matchers::Message("no such slot"));
}

TEST_CASE("disconnect - successful disconnection") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);

	CHECK_FALSE(pip.get_dependencies(source).empty());
	CHECK(pip.is_valid());

	pip.disconnect(source, sink);

	CHECK(pip.get_dependencies(source).empty());
	CHECK_FALSE(pip.is_valid());
}

TEST_CASE("disconnect - If the provided nodes are not connected, nothing is done.") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	CHECK_NOTHROW(pip.disconnect(source, sink));
	CHECK_FALSE(pip.is_valid());
}

TEST_CASE("disconnect - pipeline_error - invalid_node_id") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();
	pip.connect(source, sink, 0);

	CHECK_THROWS_MATCHES(pip.disconnect(source, 9), ppl::pipeline_error, Catch::Matchers::Message("invalid node ID"));
	CHECK_THROWS_MATCHES(pip.disconnect(9, sink), ppl::pipeline_error, Catch::Matchers::Message("invalid node ID"));
}

TEST_CASE("get_dependencies - successful") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink1 = pip.create_node<sink_print<int>>();
	const auto sink2 = pip.create_node<sink_print<int>>();
	const auto sink3 = pip.create_node<sink_print<int>>();

	pip.connect(source, sink1, 0);
	pip.connect(source, sink2, 0);
	pip.connect(source, sink3, 0);

	CHECK(pip.get_dependencies(source).size() == 3);
	CHECK(pip.get_dependencies(source)[0] == std::make_pair(sink1, 0));
	CHECK(pip.get_dependencies(source)[1] == std::make_pair(sink2, 0));
	CHECK(pip.get_dependencies(source)[2] == std::make_pair(sink3, 0));
}

TEST_CASE("get_dependencies - invalid source") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);
	CHECK_THROWS_MATCHES(pip.get_dependencies(9), ppl::pipeline_error, Catch::Matchers::Message("invalid node ID"));
}

// ########################################
// 		Validation and Execution
// ########################################

TEST_CASE("is_valid - simple valid pipeline") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);

	CHECK(pip.is_valid());
}

TEST_CASE("is_valid - There are no subpipelines") {
	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink2 = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);

	pip.connect(source2, sink2, 0);

	CHECK_FALSE(pip.is_valid());
}

TEST_CASE("is_valid - There are no subpipelines 2") {
	auto pip = ppl::pipeline{};
	const auto source1 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto component = pip.create_node<component_add<int, int, int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	const auto source3 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink2 = pip.create_node<sink_print<int>>();

	pip.connect(source1, component, 0);
	pip.connect(source2, component, 1);
	pip.connect(component, sink, 0);

	pip.connect(source3, sink2, 0);

	CHECK_FALSE(pip.is_valid());
}

TEST_CASE("is_valid - All source slots for all nodes must be filled.") {
	SECTION("one extra source") {
		auto pip = ppl::pipeline{};
		const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
		pip.create_node<source_produce_num<int, 0, 10>>();
		const auto sink = pip.create_node<sink_print<int>>();

		pip.connect(source, sink, 0);

		CHECK_FALSE(pip.is_valid());
	}

	SECTION("one extra sink") {
		auto pip = ppl::pipeline{};
		const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
		const auto sink = pip.create_node<sink_print<int>>();
		pip.create_node<sink_print<int>>();

		pip.connect(source, sink, 0);

		CHECK_FALSE(pip.is_valid());
	}
}

TEST_CASE("is_valid - All non-sink nodes must have at least one dependent.") {
	auto pip = ppl::pipeline{};
	const auto source1 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();
	const auto component = pip.create_node<component_add<int, int, int>>();

	pip.connect(source1, sink, 0);
	pip.connect(source1, component, 0);
	pip.connect(source2, component, 1);

	CHECK_FALSE(pip.is_valid());
}

TEST_CASE("is_valid - There are no cycles.") {
	SECTION("Self connect - source == dest") {
		auto pip = ppl::pipeline{};
		const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
		const auto component = pip.create_node<component_add<int, int, int>>();
		pip.connect(source, component, 0);
		pip.connect(component, component, 1);

		CHECK_FALSE(pip.is_valid());
	}

	SECTION("big cycle") {
		auto pip = ppl::pipeline{};
		const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
		const auto component1 = pip.create_node<component_add<int, int, int>>();
		const auto component2 = pip.create_node<component_double_it<int>>();
		const auto component3 = pip.create_node<component_double_it<int>>();
		const auto sink = pip.create_node<sink_print<int>>();

		pip.connect(source, component2, 0);
		pip.connect(component2, component3, 0);
		pip.connect(component3, component1, 0);
		pip.connect(component1, component1, 1);
		pip.connect(component1, sink, 0);

		CHECK_FALSE(pip.is_valid());
	}
}

TEST_CASE("step - simple successful") {
	std::string line;
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);

	CHECK(pip.is_valid());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());

	int count = 0;
	while (std::getline(buffer, line)) {
		CHECK(line == std::to_string(++count));
	}

	std::cout.rdbuf(old);
}

TEST_CASE("step - If the node is closed, close all nodes that depend on it.") {
	std::string line;
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 1>>();
	const auto component1 = pip.create_node<component_double_it<int>>();
	const auto component2 = pip.create_node<component_double_it<int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, component1, 0);
	pip.connect(component1, component2, 0);
	pip.connect(component2, sink, 0);

	CHECK(pip.is_valid());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());
	CHECK(pip.step());

	int count = 1;
	while (std::getline(buffer, line)) {
		CHECK(line == std::to_string(count++ * 2 * 2));
	}

	std::cout.rdbuf(old);
}

TEST_CASE("step - If the node has no value, skip all nodes that depend on it.") {
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto component1 = pip.create_node<component_double_it_but_skip_odd<int>>();
	const auto component2 = pip.create_node<component_double_it<int>>();
	const auto component3 = pip.create_node<component_double_it<int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, component1, 0);
	pip.connect(component1, component2, 0);
	pip.connect(component2, component3, 0);
	pip.connect(component3, sink, 0);

	CHECK(pip.is_valid());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());

	CHECK(buffer.str() == "16\n");

	std::cout.rdbuf(old);
}

TEST_CASE("step - empty case - polling a node only if all its dependencies are ready.") {
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source1 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto component1 = pip.create_node<component_double_it_but_skip_odd<int>>();
	const auto component2 = pip.create_node<component_add<int, int, int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source1, component1, 0);
	pip.connect(component1, component2, 0);
	pip.connect(source2, component2, 1);
	pip.connect(component2, sink, 0);

	CHECK(pip.is_valid());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());
	CHECK_FALSE(pip.step());

	CHECK(buffer.str() == "6\n");

	std::cout.rdbuf(old);
}

TEST_CASE("run - one source, one sink") {
	std::string line;
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source, sink, 0);

	CHECK(pip.is_valid());
	pip.run();

	int count = 0;
	while (std::getline(buffer, line)) {
		CHECK(line == std::to_string(++count));
	}
	CHECK(count == 11);

	std::cout.rdbuf(old);
}

TEST_CASE("run - four source, six component, three sink") {
	std::string line;
	std::stringstream buffer;
	std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

	auto pip = ppl::pipeline{};
	const auto source_a = pip.create_node<source_produce_num<int, 0, 100>>();
	const auto source_b = pip.create_node<source_produce_num<int, 0, 100>>();
	const auto source_c = pip.create_node<source_produce_num<std::size_t, 0, 100>>();
	const auto source_d = pip.create_node<source_produce_num<std::size_t, 0, 100>>();

	const auto component_lv1_a = pip.create_node<component_add<int, int, std::size_t>>();
	const auto component_lv1_b = pip.create_node<component_add<int, std::size_t, std::size_t>>();
	const auto component_lv1_c = pip.create_node<component_add<std::size_t, std::size_t, std::size_t>>();
	const auto component_lv2_a = pip.create_node<component_add<std::size_t, std::size_t, std::size_t>>();
	const auto component_lv2_b = pip.create_node<component_add<std::size_t, std::size_t, std::size_t>>();
	const auto component_lv3 = pip.create_node<component_add_but_skip_odd<std::size_t, std::size_t, std::size_t>>();

	const auto sink_a = pip.create_node<sink_print<std::size_t>>();
	const auto sink_b = pip.create_node<sink_print<std::size_t>>();
	const auto sink_c = pip.create_node<sink_print<std::size_t>>();

	pip.connect(source_a, component_lv1_a, 0);
	pip.connect(source_b, component_lv1_a, 1);
	pip.connect(source_b, component_lv1_b, 0);
	pip.connect(source_c, component_lv1_b, 1);
	pip.connect(source_c, component_lv1_c, 0);
	pip.connect(source_d, component_lv1_c, 1);

	pip.connect(component_lv1_a, component_lv2_a, 0);
	pip.connect(component_lv1_b, component_lv2_a, 1);
	pip.connect(component_lv1_b, component_lv2_b, 0);
	pip.connect(component_lv1_c, component_lv2_b, 1);

	pip.connect(component_lv2_a, component_lv3, 0);
	pip.connect(component_lv2_b, component_lv3, 1);

	pip.connect(component_lv2_a, sink_a, 0);
	pip.connect(component_lv3, sink_b, 0);
	pip.connect(component_lv2_b, sink_c, 0);

	CHECK(pip.is_valid());
	pip.run();

	for (int i = 1; i < 102; ++i) {
		std::getline(buffer, line);
		CHECK(line == std::to_string(i + i + i + i));
		std::getline(buffer, line);
		CHECK(line == std::to_string(i + i + i + i));
		std::getline(buffer, line);
		CHECK(line == std::to_string((i + i + i + i) * 2));
	}

	std::getline(buffer, line);
	CHECK(line.size() == 0);

	std::cout.rdbuf(old);
}

// ########################################
// 		Validation and Execution
// ########################################

TEST_CASE("std::ostream &operator<<") {
	auto pip = ppl::pipeline{};
	const auto source1 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto source2 = pip.create_node<source_produce_num<int, 0, 10>>();
	const auto component = pip.create_node<component_add<int, int, int>>();
	const auto sink = pip.create_node<sink_print<int>>();

	pip.connect(source1, component, 0);
	pip.connect(source2, component, 1);
	pip.connect(component, sink, 0);

	CHECK(pip.is_valid());

	std::stringstream buffer;

	buffer << pip;

	auto expect = R"(digraph G {
  "1 Source - produce i: 0 to 10"
  "2 Source - produce i: 0 to 10"
  "3 Component - add i i"
  "4 Sink - print"

  "1 Source - produce i: 0 to 10" -> "3 Component - add i i"
  "2 Source - produce i: 0 to 10" -> "3 Component - add i i"
  "3 Component - add i i" -> "4 Sink - print"
}
)";

	CHECK(buffer.str() == expect);
}