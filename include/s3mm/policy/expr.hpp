#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/policy/attr.hpp"

namespace s3mm::policy {

enum class Op { Eq, Ne, Lt, Le, Gt, Ge, Regex, NotRegex, In, Exists };

const char* opName(Op op);

/// AST node of a rule condition.
class Expr {
public:
    enum class Kind { All, Any, Not, Cmp, Exists };
    virtual ~Expr() = default;
    virtual Kind kind() const = 0;
    virtual bool eval(const Context& ctx) const = 0;
    virtual std::string toString() const = 0;
    /// Attributes referenced by this expression (for validation/lint).
    virtual void collectFields(std::vector<std::string>& out) const = 0;
};

using ExprPtr = std::shared_ptr<Expr>;

class AllExpr : public Expr {
public:
    explicit AllExpr(std::vector<ExprPtr> items) : items_(std::move(items)) {}
    Kind kind() const override { return Kind::All; }
    bool eval(const Context& ctx) const override;
    std::string toString() const override;
    void collectFields(std::vector<std::string>& out) const override;

private:
    std::vector<ExprPtr> items_;
};

class AnyExpr : public Expr {
public:
    explicit AnyExpr(std::vector<ExprPtr> items) : items_(std::move(items)) {}
    Kind kind() const override { return Kind::Any; }
    bool eval(const Context& ctx) const override;
    std::string toString() const override;
    void collectFields(std::vector<std::string>& out) const override;

private:
    std::vector<ExprPtr> items_;
};

class NotExpr : public Expr {
public:
    explicit NotExpr(ExprPtr inner) : inner_(std::move(inner)) {}
    Kind kind() const override { return Kind::Not; }
    bool eval(const Context& ctx) const override { return !inner_->eval(ctx); }
    std::string toString() const override { return "not (" + inner_->toString() + ")"; }
    void collectFields(std::vector<std::string>& out) const override { inner_->collectFields(out); }

private:
    ExprPtr inner_;
};

class CmpExpr : public Expr {
public:
    CmpExpr(std::string field, Op op, std::string literal, std::vector<std::string> list = {})
        : field_(std::move(field)), op_(op), literal_(std::move(literal)), list_(std::move(list)) {}
    Kind kind() const override { return Kind::Cmp; }
    bool eval(const Context& ctx) const override;
    std::string toString() const override;
    void collectFields(std::vector<std::string>& out) const override { out.push_back(field_); }

    const std::string& field() const { return field_; }
    Op op() const { return op_; }
    const std::string& literal() const { return literal_; }

private:
    std::string field_;
    Op op_;
    std::string literal_;
    std::vector<std::string> list_;
};

class ExistsExpr : public Expr {
public:
    ExistsExpr(std::string field, bool negate) : field_(std::move(field)), negate_(negate) {}
    Kind kind() const override { return Kind::Exists; }
    bool eval(const Context& ctx) const override;
    std::string toString() const override;
    void collectFields(std::vector<std::string>& out) const override { out.push_back(field_); }

private:
    std::string field_;
    bool negate_;
};

/// Compare a context attribute against a literal; shared by CmpExpr and tests.
bool compare(const PValue& left, Op op, const std::string& literal, const std::vector<std::string>& list);

} // namespace s3mm::policy
