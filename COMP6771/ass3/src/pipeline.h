#ifndef COMP6771_PIPELINE_H
#define COMP6771_PIPELINE_H

#include <algorithm>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <queue>
#include <stack>
#include <string>
#include <tuple>
#include <typeindex>
#include <typeinfo>
#include <utility>
#include <vector>

namespace ppl {

	// Errors that may occur in a pipeline.
	enum class pipeline_error_kind {
		// An expired node ID was provided.
		invalid_node_id,
		// Attempting to bind a non-existant slot.
		no_such_slot,
		// Attempting to bind to a slot that is already filled.
		slot_already_used,
		// The output type and input types for a connection don't match.
		connection_type_mismatch,
	};

	struct pipeline_error : std::exception {
		explicit pipeline_error(pipeline_error_kind kind) noexcept
		: kind_(kind) {}
		auto kind() const noexcept -> pipeline_error_kind {
			return kind_;
		}
		auto what() const noexcept -> const char* override {
			switch (kind_) {
			case pipeline_error_kind::invalid_node_id: return "invalid node ID";
			case pipeline_error_kind::no_such_slot: return "no such slot";
			case pipeline_error_kind::slot_already_used: return "slot already used";
			case pipeline_error_kind::connection_type_mismatch: return "connection type mismatch";
			}
			return "Unknown pipeline error";
		}

	 private:
		pipeline_error_kind kind_;
	};

	// The result of a poll_next() operation.
	enum class poll {
		// A value is available.
		ready,
		// No value is available this time, but there might be one later.
		empty,
		// No value is available, and there never will be again:
		// every future poll for this node will return `poll::closed` again.
		closed,
	};

	// a node generalises producer<O> over "any component at all".
	class node {
	 public:
		virtual auto name() const -> std::string = 0;
		virtual ~node() = default;

	 private:
		virtual auto poll_next() -> poll = 0;
		// Preconditions: slot is a valid index, and source is either a pointer
		// to a producer of the correct type, or nullptr.
		virtual void connect(const node* source, int slot) = 0;

		// You may add any other virtual functions you feel you may want here.
		poll poll_state = poll::ready;
		auto set_state(poll state) noexcept -> void {
			poll_state = state;
		}

		auto get_state() const noexcept -> poll {
			return poll_state;
		}

		friend class pipeline;
	};

	// A producer<O> generalises component<I, O> over "any component producing Os"
	template<typename Output>
	struct producer : node {
		using output_type = Output;
		// only when `Output` is not `void`
		// Preconditions: poll_next() has been called and last returned poll::ready.
		virtual auto value() const -> const output_type& = 0;
	};

	// Specialization for `void` output type.
	template<>
	struct producer<void> : node {
		using output_type = void;
	};

	template<typename Input, typename Output>
	struct component : producer<Output> {
		using input_type = Input;
		using output_type = Output;
	};

	template<typename Input>
	struct sink : component<std::tuple<Input>, void> {};

	template<typename Output>
	struct source : component<std::tuple<>, Output> {
	 private:
		void connect(const node* source, int slot) override {
			(void)source;
			(void)slot;
		}
	};

	// The requirements that a type `N` must satisfy
	// to be used as a component in a pipeline.
	template<typename N>
	// 3.6.0
	concept concrete_node =
	    requires {
		    typename N::input_type;
		    typename N::output_type;
		    std::tuple_size_v<typename N::input_type>;
	    } and std::derived_from<N, node> and std::derived_from<N, producer<typename N::output_type>>
	    and !std::is_abstract_v<N>;

	namespace internal {
		enum class node_type { source, sink, component };
	}

	class pipeline {
	 public:
		// 3.6.1
		using node_id = std::size_t;

		// 3.6.2
		pipeline() noexcept
		: id_counter_(0) {}
		pipeline(const pipeline&) = delete;
		pipeline(pipeline&& other) noexcept
		: id_counter_(other.id_counter_)
		, nodes_(std::move(other.nodes_))
		, dependencies_(std::move(other.dependencies_)) {}
		auto operator=(const pipeline&) -> pipeline& = delete;
		auto operator=(pipeline&& other) noexcept -> pipeline& {
			id_counter_ = other.id_counter_;
			nodes_ = std::move(other.nodes_);
			dependencies_ = std::move(other.dependencies_);
			return *this;
		}
		~pipeline() noexcept {
			nodes_.clear();
			dependencies_.clear();
		}

		// 3.6.3
		template<typename N, typename... Args>
		    requires concrete_node<N> and std::constructible_from<N, Args...>
		auto create_node(Args&&... args) -> node_id {
			auto id = ++id_counter_;
			using input_type = typename N::input_type;
			using output_type = typename N::output_type;

			auto node_input_types = std::vector<std::type_index>{};
			std::apply(
			    [&node_input_types](auto&&... types) {
				    (node_input_types.emplace_back(typeid(std::decay_t<decltype(types)>)), ...);
			    },
			    input_type{});

			internal::node_type saved_n_type = internal::node_type::component;
			if constexpr (std::is_base_of_v<source<typename N::output_type>, N>) {
				saved_n_type = internal::node_type::source;
			}
			else if constexpr (std::tuple_size_v<input_type> == 1) {
				if (std::is_base_of_v<sink<std::tuple_element_t<0, input_type>>, N>) {
					saved_n_type = internal::node_type::sink;
				}
			}

			dependencies_.emplace(id, std::vector<std::pair<node_id, int>>{});
			nodes_.emplace(id,
			               std::make_tuple(std::make_unique<N>(std::forward<Args>(args)...),
			                               std::move(node_input_types),
			                               std::type_index(typeid(output_type)),
			                               saved_n_type));
			return id;
		}

		// Remove the specified node from the pipeline. Disconnects it from any nodes it is currently connected to.
		void erase_node(node_id n_id) {
			throw_if_id_invalid(n_id);
			for (auto& node : dependencies_) {
				node.second.erase(std::remove_if(node.second.begin(),
				                                 node.second.end(),
				                                 [n_id](const auto& src) { return src.first == n_id; }),
				                  node.second.end());
			}
			dependencies_.erase(n_id);
			nodes_.erase(n_id);
		}

		// Returns: A pointer to the specified node. If node is invalid, returns nullptr instead.
		auto get_node(node_id n_id) noexcept -> node* {
			if (nodes_.find(n_id) == nodes_.end()) {
				return nullptr;
			}
			return std::get<node_ptr>(nodes_.at(n_id)).get();
		}

		// Notes: You may need more than one overload for proper const-correctness.
		auto get_node(node_id n_id) const noexcept -> const node* {
			if (nodes_.find(n_id) == nodes_.end()) {
				return nullptr;
			}
			return std::get<node_ptr>(nodes_.at(n_id)).get();
		}

		// 3.6.4
		// Connect source's output to dest's input for the given slot.
		void connect(node_id src, node_id dst, int slot) {
			//? Check if either handle is invalid
			throw_if_id_invalid(src);
			throw_if_id_invalid(dst);

			//? Check if the destination node's slot is already full
			for (auto& node : dependencies_) {
				for (auto& curr_src : node.second) {
					if (curr_src.first == dst && curr_src.second == slot) {
						throw pipeline_error(pipeline_error_kind::slot_already_used);
					}
				}
			}

			//? Check if the slot number indicated by slot does not exist
			if (slot < 0 || slot >= get_input_size(dst)) {
				throw pipeline_error(pipeline_error_kind::no_such_slot);
			}

			//? Check if the source output type does not match the destination input type on corresponding slot
			if (get_output_type(src) != get_input_type(dst, slot)) {
				throw pipeline_error(pipeline_error_kind::connection_type_mismatch);
			}

			//? Update the dependencies_ map
			dependencies_.at(src).emplace_back(dst, slot);

			//? Connect the nodes
			auto temp_src = get_node(src);
			auto temp_dst = get_node(dst);
			if (temp_src != nullptr && temp_dst != nullptr) {
				temp_dst->connect(temp_src, slot);
			}
		}

		void disconnect(node_id src, node_id dst) {
			//? Check if either handle is invalid
			throw_if_id_invalid(src);
			throw_if_id_invalid(dst);
			if (dependencies_.at(src).empty()) {
				return;
			}
			auto& src_dep = dependencies_.at(src);
			src_dep.erase(
			    std::remove_if(src_dep.begin(), src_dep.end(), [dst](const auto& curr) { return curr.first == dst; }),
			    src_dep.end());
		}

		auto get_dependencies(node_id src) const -> std::vector<std::pair<node_id, int>> {
			throw_if_id_invalid(src);
			return dependencies_.at(src);
		}

		// 3.6.5
		auto is_valid() const -> bool {
			//? All source slots for all nodes must be filled.
			int count = 0;
			for (auto& node : nodes_) {
				count += get_input_size(node.first);
			}
			for (auto& node : dependencies_) {
				count -= static_cast<int>(node.second.size());
			}
			if (count != 0) {
				return false;
			}

			//? There is at least 1 source node.
			count = 0;
			for (auto& node : nodes_) {
				if (get_node_type(node.first) == internal::node_type::source) {
					count++;
				}
			}
			if (count == 0) {
				return false;
			}

			//? There is at least 1 sink node.
			count = 0;
			for (auto& node : nodes_) {
				if (get_node_type(node.first) == internal::node_type::sink) {
					count++;
				}
			}
			if (count == 0) {
				return false;
			}

			//? All non-sink nodes must have at least one dependent.
			for (auto& node : nodes_) {
				if (dependencies_.at(node.first).empty() && get_node_type(node.first) != internal::node_type::sink) {
					return false;
				}
			}

			// //? There are no subpipelines.
			std::vector<node_id> visited{};
			std::stack<node_id> sub_stack{};

			sub_stack.push(nodes_.begin()->first);

			while (!sub_stack.empty()) {
				auto curr = sub_stack.top();
				sub_stack.pop();
				if (std::find(visited.begin(), visited.end(), curr) != visited.end()) {
					continue;
				}
				visited.push_back(curr);
				// add all dependencies of curr to the stack
				for (auto& node : dependencies_) {
					if (node.first == curr) {
						for (auto& src : node.second) {
							if (std::find(visited.begin(), visited.end(), src.first) == visited.end()) {
								sub_stack.push(src.first);
							}
						}
					}
				}
				// add all dependent of curr to the stack
				for (auto& node : dependencies_) {
					for (auto& src : node.second) {
						if (src.first == curr) {
							if (std::find(visited.begin(), visited.end(), node.first) == visited.end()) {
								sub_stack.push(node.first);
							}
						}
					}
				}
			}

			if (visited.size() != nodes_.size()) {
				return false;
			}

			//? There are no cycles. Use Kahn's algorithm
			std::map<node_id, int> in_degree{};
			std::map<node_id, std::vector<node_id>> adj_list{};
			std::queue<node_id> q{};

			// Initialize in_degree and adj_list
			for (auto& node : nodes_) {
				auto n_id = node.first;
				in_degree[n_id] = 0;
				adj_list[n_id] = std::vector<node_id>{};
			}

			// Update in_degree and adj_list
			for (auto& node : nodes_) {
				auto n_id = node.first;
				auto node_inputs = dependencies_.at(n_id);
				for (auto& src : node_inputs) {
					in_degree[src.first]++;
					adj_list[n_id].push_back(src.first);
				}
			}

			// Push all nodes with in_degree == 0 into the queue
			for (auto& it : in_degree) {
				if (it.second == 0) {
					q.push(it.first);
				}
			}

			// Pop nodes from the queue and update in_degree and adj_list
			while (!q.empty()) {
				auto curr = q.front();
				q.pop();
				for (auto& next : adj_list[curr]) {
					in_degree[next]--;
					if (in_degree[next] == 0) {
						q.push(next);
					}
				}
			}

			// Check if there is a node with in_degree > 0
			for (auto& it : in_degree) {
				if (it.second > 0) {
					return false;
				}
			}

			return true;
		}

		// Perform one tick of the pipeline.
		// Initially source nodes shall be polled, and will prepare a value.
		// According to the poll result:
		// - If the node is closed, close all nodes that depend on it.
		// - If the node has no value, skip all nodes that depend on it.
		// - Otherwise, the node has a value, and all nodes that depend on it should be polled, and so on recursively.
		// The tick ends once every node has been either polled, skipped, or closed.
		auto step() -> bool {
			auto flow = std::vector<node_id>{};
			for (auto& node : nodes_) {
				auto curr_id = node.first;
				auto curr = get_node(curr_id);
				if (curr != nullptr) {
					if (get_node_type(curr_id) == internal::node_type::source && curr->get_state() == poll::ready) {
						flow.emplace_back(curr_id);
					}
				}
			}

			while (!flow.empty()) {
				auto curr_id = flow.front();
				flow.erase(flow.begin());
				auto curr = get_node(curr_id);

				// avoid polling a node if all its dependent sink nodes are closed.
				bool all_closed = true;
				if (get_node_type(curr_id) != internal::node_type::sink) {
					for (auto& dst : dependencies_.at(curr_id)) {
						auto temp = get_node(dst.first);
						if (temp != nullptr && temp->get_state() != poll::closed) {
							all_closed = false;
							break;
						}
					}
					if (all_closed) {
						continue;
					}
				}

				// polling a node only if all its dependencies are ready.
				bool dependencies_check = false;
				for (auto& node : dependencies_) {
					for (auto& dst : node.second) {
						auto temp = get_node(node.first);
						if (dst.first == curr_id && temp->get_state() != poll::ready) {
							dependencies_check = true;
							break;
						}

					}
				}
				if (dependencies_check) {
					continue;
				}

				auto poll_state = curr->poll_next();
				if (curr != nullptr) {
					curr->set_state(poll_state);
				}

				switch (poll_state) {
				case poll::closed: recursively_close(curr_id); break;
				case poll::empty: break;
				case poll::ready:
					for (auto& dst : dependencies_.at(curr_id)) {
						auto temp = get_node(dst.first);
						if ((temp != nullptr && temp->get_state() == poll::closed)
							|| std::find(flow.begin(), flow.end(), dst.first) != flow.end())
						{
							continue;
						}
						flow.emplace_back(dst.first);
					}
					break;
				}
			}

			// Returns: true if all sink nodes are now closed, or false otherwise.
			for (auto& node : nodes_) {
				auto curr_id = node.first;
				auto curr = get_node(curr_id);
				if (curr != nullptr) {
					if (get_node_type(curr_id) == internal::node_type::sink && curr->get_state() != poll::closed) {
						return false;
					}
				}
			}

			return true;
		}

		void run() {
			if (!is_valid()) {
				return;
			}
			while (!step()) {
			}
		}

		// 3.6.6
		friend std::ostream& operator<<(std::ostream& os, const pipeline& pip) {
			auto format_node = [&pip](node_id n_id) {
				std::string n_name{};
				if (pip.get_node(n_id) != nullptr) {
					n_name = pip.get_node(n_id)->name();
				}
				else {
					n_name = "unnamed";
				}
				return "\"" + std::to_string(n_id) + " " + n_name + "\"";
			};

			os << "digraph G {" << std::endl;
			for (auto& node : pip.nodes_) {
				auto n_id = node.first;
				os << "  " << format_node(n_id) << std::endl;
			}

			os << std::endl;

			for (auto& node : pip.nodes_) {
				auto n_id = node.first;
				auto node_outputs = pip.dependencies_.at(n_id);
				for (auto& dst : node_outputs) {
					os << "  " << format_node(n_id) << " -> " << format_node(dst.first) << std::endl;
				}
			}

			os << "}" << std::endl;

			return os;
		}

	 private:
		node_id id_counter_;
		std::map<node_id, std::tuple<std::unique_ptr<node>, std::vector<std::type_index>, std::type_index, internal::node_type>>
		    nodes_{};
		std::map<node_id, std::vector<std::pair<node_id, int>>> dependencies_{};

		static const std::size_t node_ptr = 0;
		static const std::size_t input_types = 1;
		static const std::size_t output_type = 2;
		static const std::size_t n_type = 3;

		// Throws: a pipeline_error for an invalid node ID.
		void throw_if_id_invalid(node_id n_id) const {
			if (nodes_.find(n_id) == nodes_.end()) {
				throw pipeline_error(pipeline_error_kind::invalid_node_id);
			}
		}

		auto get_input_size(node_id n_id) const noexcept -> int {
			return static_cast<int>(std::get<input_types>(nodes_.at(n_id)).size());
		}

		auto get_input_type(node_id n_id, int slot) const noexcept -> std::type_index {
			return std::get<input_types>(nodes_.at(n_id)).at(static_cast<std::size_t>(slot));
		}

		auto get_output_type(node_id n_id) const noexcept -> std::type_index {
			return std::get<output_type>(nodes_.at(n_id));
		}

		auto get_node_type(node_id n_id) const noexcept -> internal::node_type {
			return std::get<n_type>(nodes_.at(n_id));
		}

		void recursively_close(node_id id) noexcept {
			auto curr = get_node(id);
			if (curr == nullptr) {
				return;
			}
			curr->set_state(poll::closed);
			for (auto& dst : dependencies_.at(id)) {
				recursively_close(dst.first);
			}
		}
	};

} // namespace ppl

#endif // COMP6771_PIPELINE_H
