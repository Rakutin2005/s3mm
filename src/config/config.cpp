#include "s3mm/config/config.hpp"

#include <filesystem>
#include <set>
#include <sstream>

#include "s3mm/common/str.hpp"
#include "s3mm/common/glob.hpp"
#include "s3mm/common/fs.hpp"

namespace s3mm::config {

// ------------------------------------------------------------------- Node ---

const std::string& Node::arg(size_t i) const {
    static const std::string empty;
    return i < args.size() ? args[i] : empty;
}

std::string Node::argOr(size_t i, const std::string& fallback) const { return i < args.size() ? args[i] : fallback; }

std::string Node::argRequired(size_t i) const {
    if (i >= args.size())
        throw ConfigError("directive '" + str() + "' requires argument #" + std::to_string(i + 1), file, line);
    return args[i];
}

const Node* Node::find(const std::string& childName) const {
    for (const auto& c : children)
        if (c.name == childName) return &c;
    return nullptr;
}

std::vector<const Node*> Node::findAll(const std::string& childName) const {
    std::vector<const Node*> out;
    for (const auto& c : children)
        if (c.name == childName) out.push_back(&c);
    return out;
}

const Node* Node::findWith(const std::string& childName, size_t minArgs) const {
    for (const auto& c : children)
        if (c.name == childName && c.args.size() >= minArgs) return &c;
    return nullptr;
}

std::string Node::value(const std::string& directive, const std::string& fallback) const {
    const Node* n = find(directive);
    if (!n || n->args.empty()) return fallback;
    return n->args[0];
}

std::string Node::valueRequired(const std::string& directive) const {
    const Node* n = find(directive);
    if (!n || n->args.empty())
        throw ConfigError("missing required directive '" + directive + "' in block '" + str() + "'", file, line);
    return n->args[0];
}

bool Node::boolValue(const std::string& directive, bool fallback) const {
    const Node* n = find(directive);
    if (!n || n->args.empty()) return fallback;
    const std::string& v = n->args[0];
    if (v == "on" || v == "true" || v == "yes" || v == "1") return true;
    if (v == "off" || v == "false" || v == "no" || v == "0") return false;
    throw ConfigError("directive '" + directive + "' expects on|off, got '" + v + "'", n->file, n->line);
}

int64_t Node::int64Value(const std::string& directive, int64_t fallback) const {
    const Node* n = find(directive);
    if (!n || n->args.empty()) return fallback;
    auto v = str::parseInt64(n->args[0]);
    if (!v) throw ConfigError("directive '" + directive + "' expects an integer, got '" + n->args[0] + "'", n->file, n->line);
    return *v;
}

std::string Node::str() const {
    std::vector<std::string> parts;
    parts.push_back(name);
    for (const auto& a : args) parts.push_back(str::quoteShell(a));
    return str::join(parts, " ");
}

std::string Node::dump(int indent) const {
    std::string pad((size_t)indent, ' ');
    if (block) {
        std::string out = pad + name;
        for (const auto& a : args) out += " " + str::quoteShell(a);
        out += " {\n";
        for (const auto& c : children) out += c.dump(indent + 4) + "\n";
        out += pad + "}";
        return out;
    }
    std::string out = pad + name;
    for (const auto& a : args) out += " " + str::quoteShell(a);
    out += ";";
    return out;
}

// ------------------------------------------------------------------ parser --

namespace {

enum class Tok { Word, Semi, LBrace, RBrace, Eof };

struct Token {
    Tok kind;
    std::string text;
    int line = 0;
};

struct Lexer {
    std::string_view text;
    std::string file;
    size_t pos = 0;
    int line = 1;

    explicit Lexer(std::string_view t, std::string f) : text(std::move(t)), file(std::move(f)) {}

    void skipWsAndComments() {
        while (pos < text.size()) {
            char c = text[pos];
            if (c == '\n') { ++line; ++pos; continue; }
            if (c == ' ' || c == '\t' || c == '\r') { ++pos; continue; }
            if (c == '#') {
                while (pos < text.size() && text[pos] != '\n') ++pos;
                continue;
            }
            if (c == '/' && pos + 1 < text.size() && text[pos + 1] == '/') {
                while (pos < text.size() && text[pos] != '\n') ++pos;
                continue;
            }
            return;
        }
    }

    Token next() {
        skipWsAndComments();
        if (pos >= text.size()) return {Tok::Eof, {}, line};
        char c = text[pos];
        if (c == ';') { ++pos; return {Tok::Semi, ";", line}; }
        if (c == '{') { ++pos; return {Tok::LBrace, "{", line}; }
        if (c == '}') { ++pos; return {Tok::RBrace, "}", line}; }
        std::string word;
        int startLine = line;
        while (pos < text.size()) {
            char ch = text[pos];
            if (ch == '\n' || ch == ' ' || ch == '\t' || ch == '\r' || ch == ';' || ch == '{' || ch == '}') break;
            if (ch == '"' || ch == '\'') {
                char q = ch;
                ++pos;
                while (pos < text.size() && text[pos] != q) {
                    if (text[pos] == '\\' && q == '"' && pos + 1 < text.size()) { word += text[pos + 1]; pos += 2; continue; }
                    if (text[pos] == '\n') ++line;
                    word += text[pos++];
                }
                if (pos >= text.size()) throw ConfigError("unterminated quote", file, startLine);
                ++pos;
                continue;
            }
            word += ch;
            ++pos;
        }
        return {Tok::Word, word, startLine};
    }
};

struct Parser {
    Lexer lex;
    Token cur;
    std::set<std::string>* includeStack;

    Parser(std::string_view text, std::string file, std::set<std::string>* stack)
        : lex(text, std::move(file)), includeStack(stack) {
        cur = lex.next();
    }

    void advance() { cur = lex.next(); }

    void parseBody(std::vector<Node>& out, bool topLevel) {
        while (true) {
            if (cur.kind == Tok::Eof) {
                if (!topLevel) throw ConfigError("unexpected end of file, '}' expected", lex.file, cur.line);
                return;
            }
            if (cur.kind == Tok::RBrace) {
                if (topLevel) throw ConfigError("unexpected '}'", lex.file, cur.line);
                return;
            }
            if (cur.kind != Tok::Word)
                throw ConfigError("directive name expected, got '" + cur.text + "'", lex.file, cur.line);

            Node node;
            node.name = cur.text;
            node.file = lex.file;
            node.line = cur.line;
            advance();

            while (cur.kind == Tok::Word) {
                node.args.push_back(str::expandEnv(cur.text));
                advance();
            }

            if (cur.kind == Tok::Semi) {
                if (node.name == "include") {
                    advance();
                    if (node.args.empty()) throw ConfigError("include requires a path", node.file, node.line);
                    expandInclude(node, out);
                    continue;
                }
                advance();
                out.push_back(std::move(node));
                continue;
            }
            if (cur.kind == Tok::LBrace) {
                node.block = true;
                advance();
                parseBody(node.children, false);
                if (cur.kind != Tok::RBrace) throw ConfigError("'}' expected", lex.file, cur.line);
                advance();
                out.push_back(std::move(node));
                continue;
            }
            throw ConfigError("';' or '{' expected after '" + node.str() + "'", lex.file, cur.line);
        }
    }

    void expandInclude(const Node& includeNode, std::vector<Node>& out) {
        std::string pattern = includeNode.args[0];
        if (!pattern.empty() && pattern[0] != '/') {
            std::string base = std::filesystem::path(includeNode.file).parent_path().string();
            pattern = fs::joinPath(base.empty() ? "." : base, pattern);
        }
        auto files = glob::expand(pattern);
        if (files.empty()) {
            // allow including an explicitly named missing file to fail loudly
            if (pattern.find('*') == std::string::npos)
                throw ConfigError("include: cannot open '" + pattern + "'", includeNode.file, includeNode.line);
            return;
        }
        for (const auto& f : files) {
            std::error_code ec;
            std::string real = std::filesystem::weakly_canonical(f, ec).string();
            if (!includeStack->insert(real).second)
                throw ConfigError("include cycle detected on '" + f + "'", includeNode.file, includeNode.line);
            auto content = s3mm::fs::readFile(f);
            if (!content) throw ConfigError("include: cannot read '" + f + "'", includeNode.file, includeNode.line);
            Parser sub(*content, f, includeStack);
            sub.parseBody(out, true);
            includeStack->erase(real);
        }
    }
};

} // namespace

Result<Config> Config::parse(const std::string& text, const std::string& filename) {
    Config cfg;
    cfg.path_ = filename;
    std::set<std::string> stack;
    try {
        Parser p(text, filename, &stack);
        p.parseBody(cfg.roots_, true);
    } catch (const Error& e) {
        return Result<Config>::failure(e.what());
    }
    for (const auto& r : cfg.roots_)
        if (r.name == "s3mm" && r.block) { cfg.s3mm_ = &r; break; }
    return Result<Config>(std::move(cfg));
}

Result<Config> Config::load(const std::string& path) {
    auto content = s3mm::fs::readFile(path);
    if (!content) return Result<Config>::failure("cannot read config file: " + path);
    return parse(*content, path);
}

// -------------------------------------------------------------- validation --

static void collectBlocks(const Node& node, const std::string& kind, std::vector<const Node*>& out) {
    for (const auto& c : node.children) {
        if (c.name == kind && c.block) out.push_back(&c);
        if (c.block) collectBlocks(c, kind, out);
    }
}

static void checkUniqueNames(const Node& root, const std::string& kind, std::vector<std::string>& errors) {
    std::set<std::string> seen;
    for (const Node* n : [&] {
             std::vector<const Node*> out;
             collectBlocks(root, kind, out);
             return out;
         }()) {
        std::string name = n->argOr(0);
        if (name.empty()) {
            errors.push_back(n->file + ":" + std::to_string(n->line) + ": block '" + kind + "' requires a name");
            continue;
        }
        if (!seen.insert(name).second)
            errors.push_back(n->file + ":" + std::to_string(n->line) + ": duplicate " + kind + " '" + name + "'");
    }
}

std::vector<std::string> Config::validate() const {
    std::vector<std::string> errors;
    if (!s3mm_) {
        errors.push_back(path_ + ": missing top-level 's3mm { ... }' block");
        return errors;
    }
    for (const char* kind : {"cluster", "credential", "policy", "replication", "target", "user"})
        checkUniqueNames(*s3mm_, kind, errors);

    std::set<std::string> clusters, credentials, policies, targets, replications;
    for (const auto& c : s3mm_->children) {
        if (c.name == "cluster" && c.block) clusters.insert(c.argOr(0));
        if (c.name == "credential" && c.block) credentials.insert(c.argOr(0));
        if (c.name == "policy" && c.block) policies.insert(c.argOr(0));
        if (c.name == "target" && c.block) targets.insert(c.argOr(0));
        if (c.name == "replication" && c.block) replications.insert(c.argOr(0));
    }
    for (const char* kind : {"cluster", "credential", "policy", "replication", "target"}) {
        for (const Node* n : [&] {
                 std::vector<const Node*> out;
                 collectBlocks(*s3mm_, kind, out);
                 return out;
             }()) {
            for (const auto& c : n->children) {
                if (c.name == "vendor" && c.args.size() == 2) continue;
                if (c.name == "cluster" && !c.args.empty() && !clusters.count(c.args[0]))
                    errors.push_back(c.file + ":" + std::to_string(c.line) + ": unknown cluster '" + c.args[0] + "'");
                if ((c.name == "policy" || c.name == "policy-bundle") && !c.args.empty() && !policies.count(c.args[0]))
                    errors.push_back(c.file + ":" + std::to_string(c.line) + ": unknown policy bundle '" + c.args[0] + "'");
                if ((c.name == "source" || c.name == "destination") && !c.args.empty() && !clusters.count(c.args[0]))
                    errors.push_back(c.file + ":" + std::to_string(c.line) + ": unknown cluster '" + c.args[0] + "'");
            }
        }
    }
    // every replication must have source and destination
    for (const Node* n : [&] {
             std::vector<const Node*> out;
             collectBlocks(*s3mm_, "replication", out);
             return out;
         }()) {
        if (!n->find("source")) errors.push_back(n->file + ":" + std::to_string(n->line) + ": replication '" + n->argOr(0) + "' has no source");
        if (!n->find("destination")) errors.push_back(n->file + ":" + std::to_string(n->line) + ": replication '" + n->argOr(0) + "' has no destination");
    }
    return errors;
}

std::string Config::dump() const {
    std::string out = "# generated by s3mm flush-config\n";
    for (const auto& r : roots_) out += r.dump() + "\n";
    return out;
}

} // namespace s3mm::config
