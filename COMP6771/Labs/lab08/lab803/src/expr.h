#ifndef COMP6771_EXPR_H
#define COMP6771_EXPR_H

#include <memory>

class expr {
 public:
	expr(std::unique_ptr<expr> lhs, std::unique_ptr<expr> rhs)
	: lhs_(std::move(lhs))
	, rhs_(std::move(rhs))
	, value_(0) {}

	expr(double value)
	: lhs_(nullptr)
	, rhs_(nullptr)
	, value_(value) {}

	virtual double eval() const = 0;
	virtual ~expr() = default;

 protected:
	std::unique_ptr<expr> lhs_;
	std::unique_ptr<expr> rhs_;
	double value_;
};

class literal : public expr {
 public:
	explicit literal(double value)
	: expr(value) {}
	double eval() const override {
		return value_;
	}
};

class plus : public expr {
 public:
	plus(std::unique_ptr<expr> lhs, std::unique_ptr<expr> rhs)
	: expr(std::move(lhs), std::move(rhs)) {}
	double eval() const override {
		return lhs_->eval() + rhs_->eval();
	}
};

class minus : public expr {
 public:
	minus(std::unique_ptr<expr> lhs, std::unique_ptr<expr> rhs)
	: expr(std::move(lhs), std::move(rhs)) {}
	double eval() const override {
		return lhs_->eval() - rhs_->eval();
	}
};

class multiply : public expr {
 public:
	multiply(std::unique_ptr<expr> lhs, std::unique_ptr<expr> rhs)
	: expr(std::move(lhs), std::move(rhs)) {}
	double eval() const override {
		return lhs_->eval() * rhs_->eval();
	}
};

class divide : public expr {
 public:
	divide(std::unique_ptr<expr> lhs, std::unique_ptr<expr> rhs)
	: expr(std::move(lhs), std::move(rhs)) {}
	double eval() const override {
		return lhs_->eval() / rhs_->eval();
	}
};

#endif // COMP6771_EXPR_H
