#pragma once
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "s3mm/common/result.hpp"

namespace s3mm::xml {

struct Element {
    std::string name; // as written, may include a namespace prefix
    std::map<std::string, std::string> attrs;
    std::string text;
    std::vector<Element> children;

    /// Name without the namespace prefix ("s3:ListBucketResult" -> "ListBucketResult").
    std::string localName() const;
    const Element* child(std::string_view localName) const;
    std::vector<const Element*> childrenNamed(std::string_view localName) const;
    std::string childText(std::string_view localName, const std::string& fallback = {}) const;
};

Result<Element> parse(const std::string& document);

std::string escape(const std::string& s);
/// <name>escaped(text)</name>
std::string tag(const std::string& name, const std::string& text);
/// <name attr="v"> ... raw inner ... </name>
std::string tagRaw(const std::string& name, const std::string& attrs, const std::string& inner);

} // namespace s3mm::xml
