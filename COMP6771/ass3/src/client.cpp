/**
 * To help you get started and test that you've implemented the correct interface,
 * here is a (very simple!) example usage of the API.
 *
 * It is important that this example compiles:
 * otherwise, most of our automarking will fail on your assignment.
 *
 * We start off by including some libraries we'll need.
 */

#include "./pipeline.h"

#include <fstream>
#include <iostream>

/**
 * First we'll make a very simple source,
 * that just generates the numbers 1 through 10, and then stops.
 * Note that `poll_next()` is used to advance to the next number (once),
 * and then `value()` may be called many times repeatedly to retrieve that number.
 * Because this is a `source`, we don't need to define `connect()`,
 * as we have no inputs.
 */

// a simple source that generates the numbers 1 through 10
struct simple_source : ppl::source<int> {
	int current_value = 0;
	simple_source() = default;

	auto name() const -> std::string override {
		return "SimpleSource";
	}

	auto poll_next() -> ppl::poll override {
		if (current_value >= 10)
			return ppl::poll::closed;
		++current_value;
		return ppl::poll::ready;
	}

	auto value() const -> const int& override {
		return current_value;
	}
};

/**
 * We also need a sink to do something with our results.
 * In this case, our sink will just write to std::cout.
 * Because this is a sink, we don't need to define value(),
 * as we have no outputs.
 * That said, we _do_ need to define connect(), to learn about our input.
 * Again, note that poll_next() performs the action.
 */

// a simple sink that writes the numbers to std::cout
struct simple_sink : ppl::sink<int> {
	const ppl::producer<int>* slot0 = nullptr;

	simple_sink() = default;

	auto name() const -> std::string override {
		return "SimpleSink";
	}

	void connect(const ppl::node* src, int slot) override {
		if (slot == 0) {
			slot0 = static_cast<const ppl::producer<int>*>(src);
		}
	}

	auto poll_next() -> ppl::poll override {
		std::cout << slot0->value() << '\n';
		return ppl::poll::ready;
	}
};

/**
 * Note the unchecked downcast in `connect()`:
 * it is up to your `pipeline` implementation to ensure that
 * `connect()` is not called with bad arguments.
 *
 * From here, we just need to wire together our very simple pipeline,
 * and run it to completion:
 */

int main() {
	auto pipeline = ppl::pipeline{};

	const auto source = pipeline.create_node<simple_source>();
	const auto sink = pipeline.create_node<simple_sink>();
	pipeline.connect(source, sink, 0);

	if (auto output = std::ofstream("client.dot")) {
		output << pipeline;
	}

	pipeline.run();
}

/**
 * For the sake of the example, we also write out the dependency graph.
 * This should create a file, `client.dot, in your current working directory.
 * By running it through `dot -Tsvg client.dot -o client.svg`, you should see some
 * nicely formatted output!
 */
