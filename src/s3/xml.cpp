#include "s3mm/s3/xml.hpp"

#include <cctype>
#include <cstring>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::xml {

std::string Element::localName() const {
    auto pos = name.find(':');
    return pos == std::string::npos ? name : name.substr(pos + 1);
}

const Element* Element::child(std::string_view local) const {
    for (const auto& c : children)
        if (c.localName() == local) return &c;
    return nullptr;
}

std::vector<const Element*> Element::childrenNamed(std::string_view local) const {
    std::vector<const Element*> out;
    for (const auto& c : children)
        if (c.localName() == local) out.push_back(&c);
    return out;
}

std::string Element::childText(std::string_view local, const std::string& fallback) const {
    const Element* c = child(local);
    return c ? c->text : fallback;
}

std::string escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string tag(const std::string& name, const std::string& text) {
    return "<" + name + ">" + escape(text) + "</" + name + ">";
}

std::string tagRaw(const std::string& name, const std::string& attrs, const std::string& inner) {
    std::string out = "<" + name;
    if (!attrs.empty()) out += " " + attrs;
    out += ">" + inner + "</" + name + ">";
    return out;
}

namespace {

struct Parser {
    std::string_view doc;
    size_t pos = 0;
    std::string error;

    bool eof() const { return pos >= doc.size(); }
    char peek() const { return eof() ? '\0' : doc[pos]; }

    void skipWs() {
        while (!eof() && std::isspace((unsigned char)doc[pos])) ++pos;
    }

    bool skipUntil(const char* marker) {
        auto p = doc.find(marker, pos);
        if (p == std::string_view::npos) return false;
        pos = p + std::strlen(marker);
        return true;
    }

    bool fail(const std::string& m) {
        if (error.empty()) error = m + " at offset " + std::to_string(pos);
        return false;
    }

    std::string readName() {
        size_t start = pos;
        while (!eof() && (std::isalnum((unsigned char)doc[pos]) || doc[pos] == '_' || doc[pos] == '-' ||
                          doc[pos] == ':' || doc[pos] == '.'))
            ++pos;
        return std::string(doc.substr(start, pos - start));
    }

    std::string decodeEntities(const std::string& s) {
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] != '&') { out += s[i]; continue; }
            size_t semi = s.find(';', i);
            if (semi == std::string::npos) { out += s[i]; continue; }
            std::string ent = s.substr(i + 1, semi - i - 1);
            if (ent == "lt") out += '<';
            else if (ent == "gt") out += '>';
            else if (ent == "amp") out += '&';
            else if (ent == "quot") out += '"';
            else if (ent == "apos") out += '\'';
            else if (!ent.empty() && ent[0] == '#') {
                int code = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X') ? (int)std::strtol(ent.c_str() + 2, nullptr, 16)
                                                                             : (int)std::strtol(ent.c_str() + 1, nullptr, 10);
                out += (char)code;
            } else {
                out += s.substr(i, semi - i + 1);
            }
            i = semi;
        }
        return out;
    }

    bool parseElement(Element& out) {
        skipWs();
        if (peek() != '<') return fail("expected '<'");
        ++pos;
        if (peek() == '/') return fail("unexpected closing tag");
        out.name = readName();
        if (out.name.empty()) return fail("expected element name");
        // attributes
        while (true) {
            skipWs();
            if (eof()) return fail("unterminated start tag");
            if (peek() == '/') {
                ++pos;
                if (peek() != '>') return fail("expected '>'");
                ++pos;
                return true;
            }
            if (peek() == '>') { ++pos; break; }
            std::string attrName = readName();
            skipWs();
            if (peek() != '=') return fail("expected '=' in attribute");
            ++pos;
            skipWs();
            char quote = peek();
            if (quote != '"' && quote != '\'') return fail("expected quoted attribute value");
            ++pos;
            size_t start = pos;
            while (!eof() && doc[pos] != quote) ++pos;
            out.attrs[attrName] = decodeEntities(std::string(doc.substr(start, pos - start)));
            ++pos;
        }
        // content
        while (true) {
            if (eof()) return fail("unterminated element <" + out.name + ">");
            if (peek() == '<') {
                if (pos + 1 < doc.size() && doc[pos + 1] == '/') {
                    pos += 2;
                    std::string closing = readName();
                    skipWs();
                    if (peek() != '>') return fail("expected '>' in closing tag");
                    ++pos;
                    if (closing != out.name) return fail("mismatched closing tag </" + closing + "> for <" + out.name + ">");
                    return true;
                }
                if (pos + 3 < doc.size() && doc.substr(pos, 4) == "<!--") {
                    if (!skipUntil("-->")) return fail("unterminated comment");
                    continue;
                }
                if (pos + 1 < doc.size() && doc[pos + 1] == '?') {
                    if (!skipUntil("?>")) return fail("unterminated processing instruction");
                    continue;
                }
                Element child;
                if (!parseElement(child)) return false;
                out.children.push_back(std::move(child));
                continue;
            }
            size_t start = pos;
            while (!eof() && doc[pos] != '<') ++pos;
            out.text += decodeEntities(std::string(doc.substr(start, pos - start)));
        }
    }
};

} // namespace

static Result<Element> parseFailure(const std::string& document, size_t pos, const std::string& why) {
    if (document.empty()) LOG_DEBUG("xml: cannot parse empty document: ", why);
    else LOG_WARN("xml: parse failure at offset ", pos, " of ", document.size(), " bytes: ", why, "; document: ", log::clip(document, 200));
    return Result<Element>::failure(why);
}

Result<Element> parse(const std::string& document) {
    Parser p{document, 0, {}};
    // skip prologue
    p.skipWs();
    while (!p.eof() && p.peek() == '<') {
        if (p.doc.substr(p.pos, 2) == "<?") {
            if (!p.skipUntil("?>")) return parseFailure(document, p.pos, "unterminated XML prologue");
        } else if (p.doc.substr(p.pos, 9) == "<!DOCTYPE") {
            if (!p.skipUntil(">")) return parseFailure(document, p.pos, "unterminated DOCTYPE");
        } else if (p.doc.substr(p.pos, 4) == "<!--") {
            if (!p.skipUntil("-->")) return parseFailure(document, p.pos, "unterminated comment");
        } else {
            break;
        }
        p.skipWs();
    }
    Element root;
    if (!p.parseElement(root)) return parseFailure(document, p.pos, p.error);
    return Result<Element>(std::move(root));
}

} // namespace s3mm::xml
