#include <spelunk/analysis/kismet.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <expected>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/common/error.hpp>
#include <spelunk/common/text.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {
namespace {

struct TextNode {
    std::string text;
    std::vector<TextNode> children;
};

struct IndentedLine {
    std::size_t indent = 0;
    std::string text;
};

[[nodiscard]] std::string strip_opcode(std::string_view text) {
    text = trim_space(text);
    if (!text.empty() && text.front() == '$') {
        const std::size_t colon = text.find(':');
        if (colon != std::string_view::npos) text = trim_space(text.substr(colon + 1));
    }
    return std::string(text);
}

[[nodiscard]] std::optional<u64> parse_hex(std::string_view token) {
    if (token.starts_with("0x") || token.starts_with("0X")) token.remove_prefix(2);
    u64 value = 0;
    const auto result = std::from_chars(
        token.data(), token.data() + token.size(), value, 16);
    if (token.empty() || result.ec != std::errc{} ||
        result.ptr != token.data() + token.size()) return std::nullopt;
    return value;
}

[[nodiscard]] std::optional<u64> parse_decimal(std::string_view token) {
    u64 value = 0;
    const auto result = std::from_chars(
        token.data(), token.data() + token.size(), value, 10);
    if (token.empty() || result.ec != std::errc{} ||
        result.ptr != token.data() + token.size()) return std::nullopt;
    return value;
}

[[nodiscard]] std::optional<u64> label_offset(std::string_view line) {
    line = trim_space(line);
    constexpr std::string_view prefix = "Label_0x";
    if (!line.starts_with(prefix)) return std::nullopt;
    const std::size_t colon = line.find(':', prefix.size());
    if (colon == std::string_view::npos) return std::nullopt;
    return parse_hex(line.substr(prefix.size(), colon - prefix.size()));
}

[[nodiscard]] std::optional<u64> jump_target(std::string_view operation) {
    constexpr std::string_view marker = "offset 0x";
    const std::size_t at = operation.find(marker);
    if (at == std::string_view::npos) return std::nullopt;
    const std::size_t start = at + marker.size();
    std::size_t end = start;
    while (end < operation.size() &&
           std::isxdigit(static_cast<unsigned char>(operation[end]))) ++end;
    return parse_hex(operation.substr(start, end - start));
}

[[nodiscard]] std::optional<u64> flow_push_target(std::string_view operation) {
    constexpr std::string_view prefix = "FlowStack.Push(0x";
    if (!operation.starts_with(prefix)) return std::nullopt;
    const std::size_t end = operation.find(')', prefix.size());
    if (end == std::string_view::npos) return std::nullopt;
    return parse_hex(operation.substr(prefix.size(), end - prefix.size()));
}

[[nodiscard]] bool is_flow_pop_if(std::string_view operation) {
    return operation.starts_with(
        "if (!condition) { if (FlowStack.Num()) { jump to statement at FlowStack.Pop()");
}

[[nodiscard]] bool is_flow_pop(std::string_view operation) {
    return !is_flow_pop_if(operation) && operation.starts_with(
        "if (FlowStack.Num()) { jump to statement at FlowStack.Pop()");
}

[[nodiscard]] std::string flow_state_key(u64 offset, const std::vector<u64>& stack) {
    std::string key = std::format("{:x}", offset);
    for (const u64 target : stack) key += std::format(":{:x}", target);
    return key;
}

[[nodiscard]] std::vector<TextNode>
parse_nodes(const std::vector<IndentedLine>& lines, std::size_t& index,
            std::size_t parent_indent) {
    std::vector<TextNode> result;
    while (index < lines.size() && lines[index].indent > parent_indent) {
        TextNode node;
        node.text = lines[index].text;
        const std::size_t indent = lines[index].indent;
        ++index;
        node.children = parse_nodes(lines, index, indent);
        result.push_back(std::move(node));
    }
    return result;
}

[[nodiscard]] std::vector<TextNode> block_nodes(const KismetBlock& block) {
    std::vector<IndentedLine> lines;
    lines.reserve(block.lines.size());
    for (const auto& raw : block.lines) {
        std::size_t indent = 0;
        while (indent < raw.size() && raw[indent] == ' ') ++indent;
        const std::string_view content = trim_space(std::string_view(raw).substr(indent));
        if (!content.empty()) lines.push_back({indent, std::string(content)});
    }
    if (lines.empty()) return {};
    std::size_t index = 0;
    return parse_nodes(lines, index, lines.front().indent == 0 ? 0 : lines.front().indent - 1);
}

[[nodiscard]] const TextNode* child_named(const TextNode& node, std::string_view name) {
    for (const auto& child : node.children) {
        if (trim_space(child.text) == name) return &child;
    }
    return nullptr;
}

[[nodiscard]] const TextNode* first_expression(const TextNode& node) {
    const std::string stripped = strip_opcode(node.text);
    if (!node.text.empty() && trim_space(node.text).starts_with("$")) return &node;
    for (const auto& child : node.children) {
        if (const TextNode* result = first_expression(child)) return result;
    }
    (void)stripped;
    return nullptr;
}

[[nodiscard]] std::string friendly_name(std::string_view input) {
    std::string value(input);
    const std::size_t parameter_flags = value.find(". Parameter flags:");
    if (parameter_flags != std::string::npos) value.resize(parameter_flags);
    while (!value.empty() && value.back() == '.') value.pop_back();
    if (!value.empty() && value.back() == '?') value.pop_back();

    const std::size_t guid_sep = value.rfind('_');
    if (guid_sep != std::string::npos && value.size() - guid_sep - 1 == 32) {
        const std::string_view tail(value.data() + guid_sep + 1, 32);
        if (std::ranges::all_of(tail, [](char raw) {
                return std::isxdigit(static_cast<unsigned char>(raw));
            })) {
            const std::size_t number_sep = value.rfind('_', guid_sep - 1);
            if (number_sep != std::string::npos) value.resize(number_sep);
        }
    }
    for (char& c : value) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != ':') c = '_';
    }
    return value;
}

struct VariableInfo {
    std::string type;
    std::string name;
    bool local = false;
    bool instance = false;
    bool out = false;
};

[[nodiscard]] std::optional<VariableInfo> parse_variable(std::string_view description) {
    description = trim_space(description);
    const bool out = description.starts_with("Local out variable of type ");
    const bool local = description.starts_with("Local variable of type ") || out;
    const bool instance = description.starts_with("Instance variable of type ");
    if (!local && !instance) return std::nullopt;
    constexpr std::string_view type_marker = "variable of type ";
    const std::size_t type_at = description.find(type_marker);
    const std::size_t name_at = description.find(" named ", type_at);
    if (type_at == std::string_view::npos || name_at == std::string_view::npos) {
        return std::nullopt;
    }
    VariableInfo result;
    const std::size_t type_start = type_at + type_marker.size();
    result.type = std::string(description.substr(type_start, name_at - type_start));
    result.name = friendly_name(description.substr(name_at + 7));
    result.local = local;
    result.instance = instance;
    result.out = out;
    return result;
}

[[nodiscard]] std::string render_expr(const TextNode& node);

[[nodiscard]] std::string render_marker_expr(
    const TextNode& node, std::string_view marker) {
    if (const TextNode* wrapper = child_named(node, marker)) {
        if (const TextNode* expression = first_expression(*wrapper)) {
            return render_expr(*expression);
        }
    }
    return "/* missing expression */";
}

[[nodiscard]] std::vector<std::string> direct_arguments(const TextNode& node) {
    std::vector<std::string> arguments;
    for (const auto& child : node.children) {
        if (!trim_space(child.text).starts_with("$")) continue;
        const std::string operation = strip_opcode(child.text);
        if (operation == "EX_EndFunctionParms") continue;
        arguments.push_back(render_expr(child));
    }
    return arguments;
}

[[nodiscard]] std::string join_arguments(const std::vector<std::string>& arguments) {
    std::string result;
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        if (i != 0) result += ", ";
        result += arguments[i];
    }
    return result;
}

[[nodiscard]] std::string render_call(
    std::string name, const std::vector<std::string>& arguments) {
    if (name.ends_with("::Conv_BoolToDouble") && arguments.size() == 1) {
        return "(double)" + arguments[0];
    }
    if (name.ends_with("::SelectFloat") && arguments.size() == 3) {
        return "(" + arguments[2] + " ? " + arguments[0] + " : " + arguments[1] + ")";
    }
    if (name.ends_with("::NotEqual_ByteByte") && arguments.size() == 2) {
        return "(" + arguments[0] + " != " + arguments[1] + ")";
    }
    for (const auto& [suffix, operation] : {
             std::pair<std::string_view, std::string_view>{"::Add_DoubleDouble", "+"},
             {"::Add_IntInt", "+"},
             {"::Multiply_DoubleDouble", "*"},
             {"::Divide_DoubleDouble", "/"},
             {"::Less_DoubleDouble", "<"},
             {"::Less_IntInt", "<"},
             {"::Greater_DoubleDouble", ">"},
             {"::NotEqual_DoubleDouble", "!="},
             {"::BooleanOR", "||"},
             {"::BooleanAND", "&&"},
         }) {
        if (name.ends_with(suffix) && arguments.size() == 2) {
            return "(" + arguments[0] + " " + std::string(operation) + " " +
                   arguments[1] + ")";
        }
    }
    if ((name.ends_with("::IsValid") || name.ends_with("::GetGameInstance") ||
         name.ends_with("::GetTransform")) && name.contains("::")) {
        name.erase(0, name.rfind("::") + 2);
    }
    return name + "(" + join_arguments(arguments) + ")";
}

[[nodiscard]] std::string stack_node_name(std::string_view operation) {
    const std::size_t marker = operation.find("stack node ");
    if (marker == std::string_view::npos) return {};
    const std::size_t start = marker + 11;
    const std::size_t end = operation.find(')', start);
    return friendly_name(operation.substr(
        start, end == std::string_view::npos ? operation.size() - start : end - start));
}

[[nodiscard]] std::string render_expr(const TextNode& node) {
    const std::string operation = strip_opcode(node.text);
    if (auto variable = parse_variable(operation)) {
        return variable->instance ? "this->" + variable->name : variable->name;
    }
    if (operation == "EX_Self") return "this";
    if (operation == "EX_True") return "true";
    if (operation == "EX_False") return "false";
    if (operation == "EX_NoObject") return "nullptr";
    if (operation == "EX_Nothing") return {};
    if (operation.starts_with("EX_ObjectConst (")) {
        const std::size_t colon = operation.find(':');
        const std::size_t space = operation.find(' ', colon + 1);
        if (colon != std::string::npos) {
            return friendly_name(operation.substr(
                colon + 1,
                space == std::string::npos ? operation.size() - colon - 1
                                           : space - colon - 1));
        }
    }

    for (const std::string_view literal : {
             "literal double ", "literal float ", "literal int32 ",
             "literal int64 ", "literal byte "}) {
        if (operation.starts_with(literal)) return operation.substr(literal.size());
    }
    if (operation.starts_with("literal name ") ||
        operation.starts_with("literal string ")) {
        const std::size_t space = operation.find(' ');
        const std::size_t second = operation.find(' ', space + 1);
        return "\"" + operation.substr(second + 1) + "\"";
    }
    if (operation.starts_with("literal ansi string ")) {
        return operation.substr(20);
    }
    if (operation.starts_with("literal struct ")) {
        const std::size_t end = operation.find(" (serialized size:");
        const std::string type = friendly_name(operation.substr(
            15, end == std::string::npos ? operation.size() - 15 : end - 15));
        return type + "{/* cooked value */}";
    }

    if (operation.starts_with("Call Math") ||
        operation.starts_with("Final Function") ||
        operation.starts_with("Local Final Script Function")) {
        std::string name = stack_node_name(operation);
        if (name.empty()) name = "unknown_call";
        return render_call(std::move(name), direct_arguments(node));
    }
    if (operation.starts_with("Local Virtual Script Function named ")) {
        const std::string name = friendly_name(operation.substr(36));
        return name + "(" + join_arguments(direct_arguments(node)) + ")";
    }
    if (operation.starts_with("Virtual Function named ")) {
        return friendly_name(operation.substr(23)) +
               "(" + join_arguments(direct_arguments(node)) + ")";
    }
    if (operation.starts_with("DynamicCast to ")) {
        const std::size_t end = operation.find(" of expr:");
        const std::string type = friendly_name(operation.substr(
            15, end == std::string::npos ? operation.size() - 15 : end - 15));
        const auto arguments = direct_arguments(node);
        return "cast<" + type + ">(" +
               (arguments.empty() ? std::string("nullptr") : arguments.front()) + ")";
    }
    if (operation == "Context" || operation == "EX_InterfaceContext:") {
        const std::string object = render_marker_expr(node, "ObjectExpression:");
        std::string context = render_marker_expr(node, "ContextExpression:");
        if (operation == "EX_InterfaceContext:") {
            for (const auto& child : node.children) {
                if (const TextNode* expression = first_expression(child)) {
                    return render_expr(*expression);
                }
            }
        }
        if (context == "/* missing expression */") {
            for (const auto& child : node.children) {
                const std::string text = strip_opcode(child.text);
                if (text.starts_with("R-Value Property: ") &&
                    !text.ends_with("(null)")) {
                    context = friendly_name(text.substr(18));
                    break;
                }
            }
        }
        if (context.starts_with("this->")) context.erase(0, 6);
        if (context.contains("::") && context.starts_with(object + "::")) return context;
        return object + "->" + context;
    }
    if (operation.starts_with("Struct member context")) {
        std::string member = "member";
        for (const auto& child : node.children) {
            const std::string text = strip_opcode(child.text);
            if (text.starts_with("Member named ")) {
                const std::size_t at = text.find(" @ offset");
                member = friendly_name(text.substr(
                    13, at == std::string::npos ? text.size() - 13 : at - 13));
            }
        }
        return render_marker_expr(node, "Expression to struct:") + "." + member;
    }
    if (operation.starts_with("Cast of type")) {
        std::string target = "auto";
        if (operation.contains("FloatToDouble")) target = "double";
        else if (operation.contains("DoubleToFloat")) target = "float";
        else if (operation.contains("ObjectToBool") ||
                 operation.contains("InterfaceToBool")) target = "bool";
        return "(" + target + ")" + render_marker_expr(node, "Argument:");
    }
    if (operation.starts_with("ObjToInterfaceCast to ")) {
        const auto arguments = direct_arguments(node);
        return "cast<" + friendly_name(operation.substr(22)) + ">(" +
               (arguments.empty() ? std::string("nullptr") : arguments.front()) + ")";
    }
    return "/* " + operation + " */";
}

[[nodiscard]] std::string statement_for(
    const TextNode& node, std::unordered_set<std::string>& declared) {
    const std::string operation = strip_opcode(node.text);
    if (operation.starts_with("Let (Variable = Expression)") ||
        operation.starts_with("LetBool (Variable = Expression)") ||
        operation.starts_with("Let Obj (Variable = Expression)")) {
        const TextNode* variable_wrapper = child_named(node, "Variable:");
        const TextNode* expression_wrapper = child_named(node, "Expression:");
        if (!variable_wrapper || !expression_wrapper) return "/* malformed Let */";
        const TextNode* variable_node = first_expression(*variable_wrapper);
        const TextNode* expression_node = first_expression(*expression_wrapper);
        if (!variable_node || !expression_node) return "/* malformed Let */";
        const std::string lhs = render_expr(*variable_node);
        const std::string rhs = render_expr(*expression_node);
        if (auto variable = parse_variable(strip_opcode(variable_node->text));
            variable && variable->local && !variable->out &&
            declared.insert(variable->name).second) {
            return variable->type + " " + lhs + " = " + rhs + ";";
        }
        return lhs + " = " + rhs + ";";
    }
    if (operation == "LetValueOnPersistentFrame") {
        std::string destination = "persistent_value";
        for (const auto& child : node.children) {
            const std::string text = strip_opcode(child.text);
            if (text.starts_with("Destination variable: ")) {
                const std::size_t comma = text.find(',');
                destination = friendly_name(text.substr(
                    22, comma == std::string::npos ? text.size() - 22 : comma - 22));
            }
        }
        return destination + " = " + render_marker_expr(node, "Expression:") + ";";
    }
    if (operation.starts_with("Jump to offset 0x")) {
        const auto target = jump_target(operation).value_or(0);
        if (operation.contains(" if not expr:")) {
            const std::string condition = node.children.empty()
                ? "condition" : render_expr(node.children.front());
            return std::format("if (!({})) goto label_{:x};", condition, target);
        }
        return std::format("goto label_{:x};", target);
    }
    if (operation.starts_with("Computed Jump")) {
        const std::string target = node.children.empty()
            ? "EntryPoint" : render_expr(node.children.front());
        return "goto *" + target + ";";
    }
    if (operation.starts_with("Return expression")) {
        const std::string value = node.children.empty()
            ? std::string() : render_expr(node.children.front());
        return value.empty() ? "return;" : "return " + value + ";";
    }
    if (operation == "EX_EndOfScript") return {};
    const std::string expression = render_expr(node);
    return expression.empty() ? std::string() : expression + ";";
}

[[nodiscard]] std::string simple_function_name(std::string_view path) {
    const std::size_t colon = path.rfind(':');
    std::string name = friendly_name(
        colon == std::string_view::npos ? path : path.substr(colon + 1));
    constexpr std::string_view delegate_suffix = "__DelegateSignature";
    if (name.ends_with(delegate_suffix)) name.resize(name.size() - delegate_suffix.size());
    if (const std::size_t on = name.rfind("_On"); on != std::string::npos) {
        name.erase(0, on + 1);
    } else if (const std::size_t marker = name.find("K2Node_ComponentBoundEvent_");
               marker != std::string::npos) {
        const std::size_t event = name.find('_', marker + 27);
        if (event != std::string::npos) name.erase(0, event + 1);
    }
    return name;
}

void collect_local_variables(
    const TextNode& node, std::map<std::string, std::string>& variables) {
    if (auto variable = parse_variable(strip_opcode(node.text));
        variable && variable->local && !variable->out) {
        variables.try_emplace(variable->name, variable->type);
    }
    for (const auto& child : node.children) collect_local_variables(child, variables);
}

[[nodiscard]] std::vector<u64> reachable_offsets(
    const KismetCfg& cfg, std::optional<u64> entry) {
    if (!entry) {
        std::vector<u64> all;
        all.reserve(cfg.blocks.size());
        for (const auto& block : cfg.blocks) all.push_back(block.offset);
        return all;
    }
    std::unordered_map<u64, const KismetBlock*> by_offset;
    for (const auto& block : cfg.blocks) by_offset.emplace(block.offset, &block);
    std::vector<u64> work{*entry};
    std::unordered_set<u64> seen;
    std::vector<u64> result;
    while (!work.empty()) {
        const u64 offset = work.back();
        work.pop_back();
        if (!seen.insert(offset).second) continue;
        const auto found = by_offset.find(offset);
        if (found == by_offset.end()) continue;
        result.push_back(offset);
        for (const u64 successor : found->second->successors) work.push_back(successor);
    }
    return result;
}

[[nodiscard]] std::unordered_map<u64, std::size_t> distances_from(
    u64 start, const std::unordered_map<u64, const KismetBlock*>& by_offset,
    const std::unordered_set<u64>& allowed) {
    std::unordered_map<u64, std::size_t> distances;
    std::vector<u64> queue{start};
    distances.emplace(start, 0);
    for (std::size_t index = 0; index < queue.size(); ++index) {
        const u64 current = queue[index];
        const auto found = by_offset.find(current);
        if (found == by_offset.end()) continue;
        const std::size_t next_distance = distances.at(current) + 1;
        for (const u64 successor : found->second->successors) {
            if (!allowed.contains(successor) || distances.contains(successor)) continue;
            distances.emplace(successor, next_distance);
            queue.push_back(successor);
        }
    }
    return distances;
}

[[nodiscard]] std::optional<u64> nearest_common_successor(
    u64 left, u64 right,
    const std::unordered_map<u64, const KismetBlock*>& by_offset,
    const std::unordered_set<u64>& allowed) {
    const auto left_distances = distances_from(left, by_offset, allowed);
    const auto right_distances = distances_from(right, by_offset, allowed);
    std::optional<u64> best;
    std::size_t best_score = std::numeric_limits<std::size_t>::max();
    for (const auto& [offset, left_distance] : left_distances) {
        const auto found = right_distances.find(offset);
        if (found == right_distances.end()) continue;
        const std::size_t score = left_distance + found->second;
        if (score < best_score || (score == best_score && (!best || offset < *best))) {
            best = offset;
            best_score = score;
        }
    }
    return best;
}

void append_line(std::string& output, std::size_t indent, std::string_view line) {
    output.append(indent, ' ');
    output += line;
    output += '\n';
}

[[nodiscard]] std::string conditional_expression(const KismetBlock& block) {
    const auto nodes = block_nodes(block);
    if (nodes.empty() || nodes.front().children.empty()) return "condition";
    return render_expr(nodes.front().children.front());
}

void emit_structured_region(
    std::string& output,
    u64 start,
    std::optional<u64> stop,
    std::size_t indent,
    const std::unordered_map<u64, const KismetBlock*>& by_offset,
    const std::unordered_set<u64>& allowed,
    std::unordered_set<std::string>& declared,
    std::unordered_set<u64> active) {
    u64 current = start;
    while (!stop || current != *stop) {
        const auto found = by_offset.find(current);
        if (found == by_offset.end() || !allowed.contains(current)) return;
        if (!active.insert(current).second) {
            append_line(output, indent, std::format("goto label_{:x};", current));
            return;
        }
        const KismetBlock& block = *found->second;
        const auto nodes = block_nodes(block);
        const std::string operation = block.lines.empty()
            ? std::string() : strip_opcode(block.lines.front());

        for (const auto& node : nodes) {
            const std::string node_operation = strip_opcode(node.text);
            if (node_operation.starts_with("Jump to offset") ||
                node_operation.starts_with("Computed Jump") ||
                node_operation.starts_with("FlowStack.Push") ||
                is_flow_pop_if(node_operation) || is_flow_pop(node_operation) ||
                node_operation.starts_with("Return expression") ||
                node_operation == "EX_EndOfScript") {
                continue;
            }
            const std::string statement = statement_for(node, declared);
            if (!statement.empty()) append_line(output, indent, statement);
        }

        if (operation.starts_with("Return expression") ||
            operation == "EX_EndOfScript" || block.successors.empty()) {
            if (operation.starts_with("Return expression")) {
                const std::string statement = nodes.empty()
                    ? std::string("return;") : statement_for(nodes.front(), declared);
                append_line(output, indent, statement.empty() ? "return;" : statement);
            }
            return;
        }
        if (block.computed_jump) {
            append_line(output, indent, "goto *EntryPoint;");
            return;
        }
        if (block.successors.size() == 1) {
            current = block.successors.front();
            continue;
        }

        const u64 taken = block.successors[0];
        const u64 fallthrough = block.successors[1];
        const std::string condition = conditional_expression(block);
        const auto join = nearest_common_successor(taken, fallthrough, by_offset, allowed);
        if (!join) {
            append_line(output, indent,
                        std::format("if (!({})) goto label_{:x};", condition, taken));
            current = fallthrough;
            continue;
        }

        if (taken == *join) {
            append_line(output, indent, "if (" + condition + ") {");
            emit_structured_region(output, fallthrough, join, indent + 2,
                                   by_offset, allowed, declared, active);
            append_line(output, indent, "}");
        } else if (fallthrough == *join) {
            append_line(output, indent, "if (!(" + condition + ")) {");
            emit_structured_region(output, taken, join, indent + 2,
                                   by_offset, allowed, declared, active);
            append_line(output, indent, "}");
        } else {
            std::string taken_body;
            std::string fallthrough_body;
            emit_structured_region(taken_body, taken, join, indent + 2,
                                   by_offset, allowed, declared, active);
            emit_structured_region(fallthrough_body, fallthrough, join, indent + 2,
                                   by_offset, allowed, declared, active);
            if (taken_body.empty() && !fallthrough_body.empty()) {
                append_line(output, indent, "if (" + condition + ") {");
                output += fallthrough_body;
                append_line(output, indent, "}");
            } else if (!taken_body.empty() && fallthrough_body.empty()) {
                append_line(output, indent, "if (!(" + condition + ")) {");
                output += taken_body;
                append_line(output, indent, "}");
            } else if (!taken_body.empty()) {
                append_line(output, indent, "if (!(" + condition + ")) {");
                output += taken_body;
                append_line(output, indent, "} else {");
                output += fallthrough_body;
                append_line(output, indent, "}");
            }
        }
        current = *join;
    }
}

[[nodiscard]] bool has_cycle(
    const std::vector<u64>& selected,
    const std::unordered_map<u64, const KismetBlock*>& by_offset) {
    const std::unordered_set<u64> allowed(selected.begin(), selected.end());
    std::unordered_set<u64> visiting;
    std::unordered_set<u64> finished;
    const auto visit = [&](const auto& self, u64 offset) -> bool {
        if (finished.contains(offset) || !allowed.contains(offset)) return false;
        if (!visiting.insert(offset).second) return true;
        const auto found = by_offset.find(offset);
        if (found != by_offset.end()) {
            for (const u64 successor : found->second->successors) {
                if (self(self, successor)) return true;
            }
        }
        visiting.erase(offset);
        finished.insert(offset);
        return false;
    };
    for (const u64 offset : selected) {
        if (visit(visit, offset)) return true;
    }
    return false;
}

}  // namespace

Result<KismetCfg> parse_kismet_cfg(std::string_view disassembly) {
    KismetCfg cfg;
    std::size_t cursor = 0;
    KismetBlock* current = nullptr;
    while (cursor <= disassembly.size()) {
        const std::size_t newline = disassembly.find('\n', cursor);
        std::string_view line = disassembly.substr(
            cursor, newline == std::string_view::npos
                ? disassembly.size() - cursor : newline - cursor);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (auto offset = label_offset(line)) {
            cfg.blocks.push_back({
                .offset = *offset,
                .lines = {},
                .successors = {},
                .computed_jump = false,
            });
            current = &cfg.blocks.back();
        } else if (current && !trim_space(line).empty() && !trim_space(line).starts_with("// Kismet")) {
            current->lines.emplace_back(line);
        }
        if (newline == std::string_view::npos) break;
        cursor = newline + 1;
    }
    if (cfg.blocks.empty()) {
        return std::unexpected(Error::invalid_format(
            "kismet: disassembly contains no labels"));
    }

    std::unordered_set<u64> offsets;
    for (const auto& block : cfg.blocks) {
        if (!offsets.insert(block.offset).second) {
            return std::unexpected(Error::invalid_format(
                std::format("kismet: duplicate label 0x{:x}", block.offset)));
        }
    }
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        KismetBlock& block = cfg.blocks[i];
        if (block.lines.empty()) continue;
        const std::string operation = strip_opcode(block.lines.front());
        if (operation.starts_with("Computed Jump")) {
            block.computed_jump = true;
        } else if (flow_push_target(operation) || is_flow_pop_if(operation) ||
                   is_flow_pop(operation)) {
            if (flow_push_target(operation) && i + 1 < cfg.blocks.size()) {
                block.successors.push_back(cfg.blocks[i + 1].offset);
            }
        } else if (operation.starts_with("Jump to offset")) {
            if (auto target = jump_target(operation)) block.successors.push_back(*target);
            if (operation.contains(" if not expr:") && i + 1 < cfg.blocks.size()) {
                block.successors.push_back(cfg.blocks[i + 1].offset);
            }
        } else if (!operation.starts_with("Return expression") &&
                   operation != "EX_EndOfScript" && i + 1 < cfg.blocks.size()) {
            block.successors.push_back(cfg.blocks[i + 1].offset);
        }
        std::erase_if(block.successors, [&](u64 target) { return !offsets.contains(target); });
    }

    struct FlowState {
        u64 offset = 0;
        std::vector<u64> stack;
    };
    std::unordered_map<u64, KismetBlock*> mutable_by_offset;
    for (auto& block : cfg.blocks) mutable_by_offset.emplace(block.offset, &block);
    std::vector<FlowState> work{{cfg.blocks.front().offset, {}}};
    std::unordered_set<std::string> seen_states;
    constexpr std::size_t max_states = 100000;
    for (std::size_t index = 0; index < work.size() && index < max_states; ++index) {
        FlowState state = std::move(work[index]);
        if (!seen_states.insert(flow_state_key(state.offset, state.stack)).second) continue;
        const auto found = mutable_by_offset.find(state.offset);
        if (found == mutable_by_offset.end()) continue;
        KismetBlock& block = *found->second;
        const std::string operation = block.lines.empty()
            ? std::string() : strip_opcode(block.lines.front());

        auto add_edge = [&](u64 target, std::vector<u64> stack) {
            if (!offsets.contains(target)) return;
            if (std::ranges::find(block.successors, target) == block.successors.end()) {
                block.successors.push_back(target);
            }
            work.push_back({target, std::move(stack)});
        };

        if (auto continuation = flow_push_target(operation)) {
            if (state.stack.size() >= 64 || block.successors.empty()) continue;
            state.stack.push_back(*continuation);
            add_edge(block.successors.front(), std::move(state.stack));
        } else if (is_flow_pop_if(operation)) {
            if (!state.stack.empty()) {
                const u64 target = state.stack.back();
                auto popped = state.stack;
                popped.pop_back();
                add_edge(target, std::move(popped));
            }
            const auto block_index = static_cast<std::size_t>(&block - cfg.blocks.data());
            if (block_index + 1 < cfg.blocks.size()) {
                add_edge(cfg.blocks[block_index + 1].offset, std::move(state.stack));
            }
        } else if (is_flow_pop(operation)) {
            if (!state.stack.empty()) {
                const u64 target = state.stack.back();
                state.stack.pop_back();
                add_edge(target, std::move(state.stack));
            }
        } else {
            for (const u64 successor : block.successors) {
                add_edge(successor, state.stack);
            }
        }
    }
    return cfg;
}

std::vector<KismetUbergraphEntry> discover_kismet_ubergraph_entries(
    std::string_view ubergraph_name,
    const std::vector<std::pair<std::string, std::string>>& function_disassemblies) {
    std::map<u64, std::string> entries;
    for (const auto& [function_path, disassembly] : function_disassemblies) {
        if (function_path.ends_with(ubergraph_name)) continue;
        std::size_t call = disassembly.find(ubergraph_name);
        while (call != std::string::npos) {
            const std::size_t next_label = disassembly.find("\nLabel_", call);
            const std::size_t literal = disassembly.find("literal int32 ", call);
            if (literal != std::string::npos &&
                (next_label == std::string::npos || literal < next_label)) {
                const std::size_t start = literal + 14;
                std::size_t end = start;
                while (end < disassembly.size() &&
                       std::isdigit(static_cast<unsigned char>(disassembly[end]))) ++end;
                if (auto offset = parse_decimal(
                        std::string_view(disassembly).substr(start, end - start))) {
                    entries.try_emplace(*offset, function_path);
                }
            }
            call = disassembly.find(ubergraph_name, call + ubergraph_name.size());
        }
    }
    std::vector<KismetUbergraphEntry> result;
    result.reserve(entries.size());
    for (auto& [offset, wrapper] : entries) {
        result.push_back({offset, std::move(wrapper)});
    }
    return result;
}

std::string emit_kismet_cfg(const KismetCfg& cfg) {
    std::string output;
    for (const auto& block : cfg.blocks) {
        output += std::format("block 0x{:x}", block.offset);
        if (block.computed_jump) output += " computed-jump";
        output += " ->";
        if (block.successors.empty()) output += " <exit>";
        for (const u64 successor : block.successors) {
            output += std::format(" 0x{:x}", successor);
        }
        output += '\n';
    }
    return output;
}

std::string emit_kismet_pseudocode(
    const KismetCfg& cfg, std::string_view function_name,
    std::optional<u64> entry_offset) {
    const std::vector<u64> selected = reachable_offsets(cfg, entry_offset);
    std::unordered_map<u64, const KismetBlock*> by_offset;
    for (const auto& block : cfg.blocks) by_offset.emplace(block.offset, &block);
    bool show_labels = false;
    for (std::size_t i = 0; i < selected.size(); ++i) {
        const KismetBlock& block = *by_offset.at(selected[i]);
        const std::optional<u64> next = i + 1 < selected.size()
            ? std::optional<u64>(selected[i + 1]) : std::nullopt;
        if (block.computed_jump || block.successors.size() > 1 ||
            (block.successors.size() == 1 && block.successors.front() != next)) {
            show_labels = true;
            break;
        }
    }

    std::string output = "void " + simple_function_name(function_name) + "() {\n";
    std::unordered_set<std::string> declared;
    if (show_labels) {
        std::map<std::string, std::string> locals;
        for (const u64 offset : selected) {
            for (const auto& node : block_nodes(*by_offset.at(offset))) {
                collect_local_variables(node, locals);
            }
        }
        for (const auto& [name, type] : locals) {
            declared.insert(name);
            output += "  " + type + " " + name + "{};\n";
        }
        if (!locals.empty()) output += '\n';
    }
    const bool can_structure = !selected.empty() &&
        !std::ranges::any_of(selected, [&](u64 offset) {
            return by_offset.at(offset)->computed_jump;
        }) && !has_cycle(selected, by_offset);
    if (can_structure) {
        const std::unordered_set<u64> selected_set(selected.begin(), selected.end());
        emit_structured_region(output, selected.front(), std::nullopt, 2,
                               by_offset, selected_set, declared, {});
        output += "}\n";
        return output;
    }
    for (std::size_t i = 0; i < selected.size(); ++i) {
        const KismetBlock& block = *by_offset.at(selected[i]);
        const std::optional<u64> next = i + 1 < selected.size()
            ? std::optional<u64>(selected[i + 1]) : std::nullopt;
        if (show_labels) output += std::format("label_{:x}:\n", block.offset);
        const auto nodes = block_nodes(block);
        const std::string block_operation = block.lines.empty()
            ? std::string() : strip_opcode(block.lines.front());
        if (flow_push_target(block_operation)) continue;
        if (is_flow_pop_if(block_operation)) {
            const std::string condition = conditional_expression(block);
            if (!block.successors.empty()) {
                output += std::format("  if (!({})) goto label_{:x};\n",
                                      condition, block.successors.front());
            }
            continue;
        }
        if (is_flow_pop(block_operation)) {
            if (!block.successors.empty()) {
                output += std::format("  goto label_{:x};\n", block.successors.front());
            }
            continue;
        }
        for (const auto& node : nodes) {
            const std::string operation = strip_opcode(node.text);
            if (operation.starts_with("Jump to offset") &&
                !operation.contains(" if not expr:") &&
                block.successors.size() == 1 && block.successors.front() == next) {
                continue;
            }
            const std::string statement = statement_for(node, declared);
            if (!statement.empty()) output += "  " + statement + "\n";
        }
    }
    output += "}\n";
    return output;
}

}  // namespace spelunk
