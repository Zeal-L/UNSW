#include "./book.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <cmath>
#include <iomanip>

book::book(const std::string& name, const std::string& author, const std::string& isbn, double price) : name_{name}, author_{author}, isbn_{isbn}, price_{price} {}

book::operator std::string() const {
    return author_ + ", " + name_;
}

const std::string& book::name() const {
    return name_;
}

const std::string& book::author() const {
    return author_;
}

const std::string& book::isbn() const {
    return isbn_;
}

const double& book::price() const {
    return price_;
}

bool operator==(const book& lhs, const book& rhs) {
    return lhs.isbn() == rhs.isbn();
}

bool operator!=(const book& lhs, const book& rhs) {
    return !(lhs == rhs);
}

bool operator<(const book& lhs, const book& rhs) {
    return lhs.isbn() < rhs.isbn();
}

std::ostream& operator<<(std::ostream& os, const book& b) {
    os << b.name() + ", " + b.author() + ", " + b.isbn() + ", $" << std::fixed << std::setprecision(2) << b.price();
    return os;
}