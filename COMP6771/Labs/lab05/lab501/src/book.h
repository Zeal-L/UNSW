#ifndef COMP6771_BOOK_H
#define COMP6771_BOOK_H

#include <string>

class book {
 public:
	book() = default;
	book(const std::string& name, const std::string& author, const std::string& isbn, double price);
	explicit operator std::string() const;
	const std::string& name() const;
	const std::string& author() const;
	const std::string& isbn() const;
	const double& price() const;

 private:
	std::string name_;
	std::string author_;
	std::string isbn_;
	double price_;
};

bool operator==(const book& lhs, const book& rhs);
bool operator!=(const book& lhs, const book& rhs);
bool operator<(const book& lhs, const book& rhs);
std::ostream& operator<<(std::ostream& os, const book& b);

#endif // COMP6771_BOOK_H
