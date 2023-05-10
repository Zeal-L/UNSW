#ifndef COMP6771_NAMESPACED_H
#define COMP6771_NAMESPACED_H

#include <string>
#include <vector>

struct celestial_body {
    std::string name;
    int pos;
};

// Hint: type aliases in modern C++ also use the "using" directive...
namespace comp6771 {
    using vector = std::vector<int>;
    using planet = celestial_body;
    namespace planets {
        using terrestrial = celestial_body;
    }
}

#endif // COMP6771_NAMESPACED_H