#ifndef COMP6771_FERRARIPP_H
#define COMP6771_FERRARIPP_H

#include <iostream>
#include <string>
#include <utility>

class ferrari {
    private:
        const std::string owner_;
        const int modelno_;
        int speed_;
    public:
        ferrari(const std::string &owner, const int modelno);
        ferrari();
        ~ferrari();
        std::pair<std::string, int> get_details() const;
        void drive(int spd = 88);
        std::string vroom() const;
};

#endif  // COMP6771_FERRARIPP_H