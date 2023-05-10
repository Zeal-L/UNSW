#include "./ferrari.h"

ferrari::ferrari(const std::string& owner, const int modelno)
: owner_(owner)
, modelno_(modelno)
, speed_(0) {}

ferrari::ferrari()
: ferrari("unknown", 6771) {}

ferrari::~ferrari() = default;

std::pair<std::string, int> ferrari::get_details() const {
	return std::make_pair(owner_, modelno_);
}

void ferrari::drive(int spd /* = 100 */) {
	speed_ = spd;
}

std::string ferrari::vroom() const {
	if (speed_ < 20) {
		return "";
	}
	else if (speed_ < 80) {
		return "vroom!!";
	}
	else {
		return "VROOOOOOOOM!!!";
	}
}
