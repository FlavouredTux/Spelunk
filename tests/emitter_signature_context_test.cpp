#include "structurer_fail_common.hpp"

#include "emitter_internal.hpp"

#include <ember/analysis/objc.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace ember;
using ember::emit::Emitter;

class AbiBinary final : public Binary {
public:
    AbiBinary(Format format, Arch arch, Endian endian)
        : format_(format), arch_(arch), endian_(endian) {}

    [[nodiscard]] Format format() const noexcept override { return format_; }
    [[nodiscard]] Arch arch() const noexcept override { return arch_; }
    [[nodiscard]] Endian endian() const noexcept override { return endian_; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return 0; }
    [[nodiscard]] std::span<const Section> sections() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const Symbol> symbols() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return {};
    }

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    Format format_;
    Arch arch_;
    Endian endian_;
    std::vector<Symbol> symbols_;
};

std::unique_ptr<Region> linear_body(addr_t block_start,
                                    IrValue returned = {}) {
    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = block_start;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->block_start = block_start;
    tail->condition = returned;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    return root;
}

IrFunction return_function(addr_t start, IrValue value) {
    IrFunction function;
    function.start = start;
    function.end = start + 4;
    function.name = std::format("signature_{:x}", start);
    IrBlock block;
    block.start = start;
    block.end = function.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(value.kind == IrValueKind::None
        ? make_ret(start) : make_ret_value(start, value));
    function.block_at[block.start] = 0;
    function.blocks.push_back(std::move(block));
    return function;
}

void test_user_variadics_names_and_zero_arity() {
    constexpr addr_t kVariadic = 0x7000;
    IrValue rdi = IrValue::make_reg(Reg::Rdi, IrType::I64);
    IrFunction function = return_function(kVariadic, rdi);
    StructuredFunction structured{
        &function, linear_body(function.start, rdi)};
    Annotations annotations;
    annotations.renames[kVariadic] = "variadic_value";
    annotations.signatures[kVariadic] = FunctionSig{
        .return_type = "u64",
        .params = {{"u64", ""}},
        .variadic = true,
    };
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value() &&
              output->find(
                  "uint64_t variadic_value(uint64_t a1, ...) {") !=
                  std::string::npos &&
              output->find("return a1;") != std::string::npos,
          "unnamed variadic parameter uses one canonical fallback name");

    constexpr addr_t kVariadicOnly = 0x7010;
    IrFunction variadic_only = return_function(
        kVariadicOnly, IrValue{});
    StructuredFunction variadic_only_structured{
        &variadic_only, linear_body(variadic_only.start)};
    annotations.renames[kVariadicOnly] = "variadic_only";
    annotations.signatures[kVariadicOnly] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = true};
    auto variadic_only_output = emitter.emit(
        variadic_only_structured, nullptr, &annotations, EmitOptions{});
    check(variadic_only_output.has_value() &&
              variadic_only_output->find("void variadic_only(...) {") !=
                  std::string::npos,
          "variadic-only signature renders an ellipsis instead of void");

    constexpr addr_t kZero = 0x7020;
    IrFunction zero = return_function(kZero, rdi);
    StructuredFunction zero_structured{
        &zero, linear_body(zero.start, rdi)};
    annotations.renames[kZero] = "explicit_zero";
    annotations.signatures[kZero] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};
    auto zero_output = emitter.emit(
        zero_structured, nullptr, &annotations, EmitOptions{});
    check(zero_output.has_value() &&
              zero_output->find("uint64_t explicit_zero(void) {") !=
                  std::string::npos &&
              zero_output->find("a1") == std::string::npos,
          "explicit zero-argument signature blocks incidental arity inference");
}

void test_bodyless_per_block_return_state_and_name() {
    constexpr addr_t kStart = 0x7100;
    IrFunction function = return_function(
        kStart, IrValue::make_imm(42, IrType::I32));
    StructuredFunction bodyless{&function, nullptr};
    PseudoCEmitter emitter;

    auto inferred = emitter.emit_per_block(
        bodyless, nullptr, nullptr, EmitOptions{});
    check(inferred.has_value() &&
              inferred->find("return;") == std::string::npos &&
              inferred->find("return ") != std::string::npos,
          "bodyless per-block output preserves an unannotated return value");

    Annotations annotations;
    annotations.renames[kStart] = "renamed_bodyless";
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    auto explicit_void = emitter.emit_per_block(
        bodyless, nullptr, &annotations, EmitOptions{});
    check(explicit_void.has_value() &&
              explicit_void->starts_with("// renamed_bodyless\n") &&
              explicit_void->find("return;\n") != std::string::npos &&
              explicit_void->find("return 42") == std::string::npos,
          "per-block output honors explicit void state and display name");

    annotations.signatures[kStart] = FunctionSig{
        .return_type = "",
        .params = {{"uint64_t", "unused"}},
        .variadic = false,
    };
    auto partial = emitter.emit_per_block(
        bodyless, nullptr, &annotations, EmitOptions{});
    check(partial.has_value() &&
              partial->find("return;") == std::string::npos &&
              partial->find("return ") != std::string::npos,
          "omitted user return type does not force bodyless output to void");
}

void test_common_analysis_names_forwarded_argument() {
    constexpr addr_t kStart = 0x7200;
    constexpr addr_t kTarget = 0x8200;
    IrFunction function;
    function.start = kStart;
    function.end = kStart + 12;
    function.name = "forwarded_argument";
    IrValue rdi = IrValue::make_reg(Reg::Rdi, IrType::I64);
    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = rdi;
    args.src_count = 1;
    IrBlock block;
    block.start = kStart;
    block.end = function.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(std::move(args));
    block.insts.push_back(make_call_imm(kStart + 4, kTarget));
    block.insts.push_back(make_ret(kStart + 8));
    function.block_at[block.start] = 0;
    function.blocks.push_back(std::move(block));
    StructuredFunction structured{
        &function, linear_body(function.start)};
    Annotations annotations;
    annotations.renames[kTarget] = "consume";
    annotations.signatures[kTarget] = FunctionSig{
        .return_type = "void",
        .params = {{"uint64_t", "payload"}},
        .variadic = false,
    };

    PseudoCEmitter emitter;
    auto source = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    StructuredFunction bodyless{&function, nullptr};
    auto blocks = emitter.emit_per_block(
        bodyless, nullptr, &annotations, EmitOptions{});
    check(source.has_value() && blocks.has_value() &&
              source->find("consume(payload);") != std::string::npos &&
              blocks->find("consume(payload);") != std::string::npos &&
              source->find("rdi") == std::string::npos &&
              blocks->find("rdi") == std::string::npos,
          "structured and per-block paths share forwarded-argument naming");
}

void test_f32_layout_and_ipa_precedence() {
    Emitter layout_emitter(nullptr);
    layout_emitter.abi = Abi::SysVAmd64;
    const auto layout = layout_emitter.abi_layout_for(FunctionSig{
        .return_type = "void",
        .params = {{"f32", "value"}},
        .variadic = false,
    });
    check(layout.size() == 1 && layout[0].reg == Reg::Xmm0 &&
              layout[0].type == IrType::F32,
          "f32 alias uses the 32-bit floating-point ABI lane");

    const auto qualified_layout = layout_emitter.abi_layout_for(FunctionSig{
        .return_type = "void",
        .params = {{"const volatile f32", "value"}},
        .variadic = false,
    });
    check(qualified_layout.size() == 1 &&
              qualified_layout[0].reg == Reg::Xmm0 &&
              qualified_layout[0].type == IrType::F32 &&
              Emitter::normalize_c_type_alias("const volatile f32") ==
                  "const volatile float",
          "qualified f32 aliases retain FP classification and normalize");

    constexpr std::array qualified_fp_types{
        std::string_view{"const f32"},
        std::string_view{"volatile f32"},
        std::string_view{"const volatile f64"},
        std::string_view{"float const"},
        std::string_view{"volatile double"},
    };
    constexpr std::array non_scalar_fp_types{
        std::string_view{"const f32*"},
        std::string_view{"f64&"},
        std::string_view{"float[4]"},
        std::string_view{"float4"},
        std::string_view{"double_buffer"},
        std::string_view{"struct float_box"},
        std::string_view{"long double"},
    };
    bool qualified_types_recognized = true;
    for (std::string_view type : qualified_fp_types) {
        qualified_types_recognized &= Emitter::is_declared_fp_scalar(type);
    }
    for (std::string_view type : non_scalar_fp_types) {
        qualified_types_recognized &= !Emitter::is_declared_fp_scalar(type);
    }
    check(qualified_types_recognized,
          "FP recognition strips qualifiers without accepting compound types");

    Emitter arm32_layout_emitter(nullptr);
    arm32_layout_emitter.abi = Abi::AapcsArm32;
    const auto arm32_layout = arm32_layout_emitter.abi_layout_for(FunctionSig{
        .return_type = "void",
        .params = {{"f32", "value"}},
        .variadic = false,
    });
    check(arm32_layout.size() == 1 &&
              arm32_layout[0].reg == Reg::ArmR0 &&
              arm32_layout[0].type == IrType::F32,
          "ARM32 routes declared f32 through r0 without losing its FP type");

    const auto arm32_import_layout =
        arm32_layout_emitter.abi_layout_for_import("sinf");
    check(arm32_import_layout.size() == 1 &&
              arm32_import_layout[0].reg == Reg::ArmR0 &&
              arm32_import_layout[0].type == IrType::F32,
          "ARM32 routes imported float parameters through r0 as F32");

    constexpr addr_t kFloatTarget = 0x7390;
    Annotations return_annotations;
    return_annotations.signatures[kFloatTarget] = FunctionSig{
        .return_type = "const f32",
        .params = {},
        .variadic = false,
    };
    Emitter arm32_return_emitter(nullptr);
    arm32_return_emitter.abi = Abi::AapcsArm32;
    arm32_return_emitter.annotations = &return_annotations;
    const IrInst float_call = make_call_imm(0x738c, kFloatTarget);
    const auto return_lane =
        arm32_return_emitter.known_call_return_lane(float_call);
    check(fp_return_reg(Abi::AapcsArm32) == Reg::ArmR0 &&
              return_lane && *return_lane == ember::emit::CallReturnLane::Floating &&
              arm32_return_emitter.call_result_reg(float_call) == Reg::ArmR0,
          "known ARM32 soft-float returns bind the r0 result lane");

    constexpr addr_t kStart = 0x7300;
    IrValue rdi = IrValue::make_reg(Reg::Rdi, IrType::I64);
    IrFunction function = return_function(kStart, rdi);
    StructuredFunction structured{
        &function, linear_body(function.start, rdi)};
    InferenceResult ipa;
    const TypeRef widget = ipa.arena.struct_t(StructInfo{
        .name = "Widget", .fields = {}, .size = 8, .align = 8});
    InferredSig signature;
    signature.params[0] = ipa.arena.ptr_t(widget);
    signature.return_type = ipa.arena.int_t(8, true, true);
    ipa.sigs[kStart] = signature;
    EmitOptions options;
    options.signatures = &ipa.sigs;
    options.type_arena = &ipa.arena;

    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, options);
    check(output.has_value() &&
              output->find("int8_t sub_7300(Widget* a1) {") !=
                  std::string::npos,
          "concrete IPA return and parameter types establish header authority");
}

void test_objc_method_metadata_precedes_block_metadata() {
    constexpr addr_t kStart = 0x7380;
    IrFunction function = return_function(kStart, IrValue{});
    StructuredFunction bodyless{&function, nullptr};

    ObjcMethod method;
    method.cls = "Widget";
    method.selector = "take:";
    method.type_encoding = "v24@0:8@16";
    method.imp = kStart;

    ObjcBlock block;
    block.invoke = kStart;
    block.signature = "i16@?0i8";

    Emitter emitter(nullptr);
    emitter.abi = Abi::SysVAmd64;
    emitter.current_objc_method = &method;
    emitter.objc_block_by_invoke.emplace(kStart, &block);

    const auto context = ember::emit::setup_signature_context(
        emitter, bodyless, nullptr, nullptr);
    const FunctionSig* effective = context.effective_metadata_signature
        ? &*context.effective_metadata_signature : nullptr;
    check(context.has_metadata_sig && effective &&
              effective->return_type == "void" &&
              effective->params.size() == 3 &&
              effective->params[0].name == "self" &&
              effective->params[1].name == "_cmd" &&
              effective->params[2].name == "take" &&
              emitter.self_arg_names[0] == "self" &&
              emitter.self_arg_names[1] == "_cmd" &&
              emitter.self_arg_names[2] == "take",
          "ObjC method metadata wins when an address is also a block invoke");
}

void test_named_integer_cast_elision_preserves_semantics() {
    constexpr addr_t kArithmetic = 0x73a0;
    IrFunction arithmetic;
    arithmetic.start = kArithmetic;
    arithmetic.end = kArithmetic + 16;
    arithmetic.name = "signed_parameter_unsigned_arithmetic";
    arithmetic.next_temp_id = 3;
    const IrValue x = IrValue::make_reg(Reg::Rdi, IrType::I64);
    const IrValue narrowed = IrValue::make_temp(0, IrType::I32);
    const IrValue widened = IrValue::make_temp(1, IrType::I64);
    const IrValue sum = IrValue::make_temp(2, IrType::I64);
    IrInst truncate;
    truncate.op = IrOp::Trunc;
    truncate.dst = narrowed;
    truncate.srcs[0] = x;
    truncate.src_count = 1;
    IrInst extend;
    extend.op = IrOp::ZExt;
    extend.dst = widened;
    extend.srcs[0] = narrowed;
    extend.src_count = 1;
    IrBlock arithmetic_block;
    arithmetic_block.start = kArithmetic;
    arithmetic_block.end = arithmetic.end;
    arithmetic_block.kind = BlockKind::Return;
    arithmetic_block.insts.push_back(std::move(truncate));
    arithmetic_block.insts.push_back(std::move(extend));
    arithmetic_block.insts.push_back(make_add(
        sum, widened, IrValue::make_imm(100, IrType::I64)));
    arithmetic_block.insts.push_back(
        make_ret_value(kArithmetic + 12, sum));
    arithmetic.block_at[kArithmetic] = 0;
    arithmetic.blocks.push_back(std::move(arithmetic_block));
    StructuredFunction arithmetic_structured{
        &arithmetic, linear_body(kArithmetic, sum)};

    Annotations annotations;
    annotations.renames[kArithmetic] = "unsigned_arithmetic";
    annotations.signatures[kArithmetic] = FunctionSig{
        .return_type = "uint64_t",
        .params = {{"int", "x"}},
        .variadic = false,
    };
    PseudoCEmitter emitter;
    auto arithmetic_output = emitter.emit(
        arithmetic_structured, nullptr, &annotations, EmitOptions{});
    check(arithmetic_output.has_value() &&
              arithmetic_output->find("(uint32_t)x + 0x64") !=
                  std::string::npos &&
              arithmetic_output->find("return x + 0x64") ==
                  std::string::npos,
          "ordinary arithmetic retains a signed-to-unsigned conversion");

    constexpr addr_t kCaller = 0x73c0;
    constexpr addr_t kCallee = 0x83c0;
    IrFunction caller;
    caller.start = kCaller;
    caller.end = kCaller + 16;
    caller.name = "call_transport_conversion";
    caller.next_temp_id = 2;
    const IrValue call_narrowed = IrValue::make_temp(0, IrType::I32);
    const IrValue call_widened = IrValue::make_temp(1, IrType::I64);
    IrInst call_truncate;
    call_truncate.op = IrOp::Trunc;
    call_truncate.dst = call_narrowed;
    call_truncate.srcs[0] = x;
    call_truncate.src_count = 1;
    IrInst call_extend;
    call_extend.op = IrOp::ZExt;
    call_extend.dst = call_widened;
    call_extend.srcs[0] = call_narrowed;
    call_extend.src_count = 1;
    IrInst arguments;
    arguments.op = IrOp::Intrinsic;
    arguments.name = "call.args.1";
    arguments.srcs[0] = call_widened;
    arguments.src_count = 1;
    IrBlock call_block;
    call_block.start = kCaller;
    call_block.end = caller.end;
    call_block.kind = BlockKind::Return;
    call_block.insts.push_back(std::move(call_truncate));
    call_block.insts.push_back(std::move(call_extend));
    call_block.insts.push_back(std::move(arguments));
    call_block.insts.push_back(make_call_imm(kCaller + 8, kCallee));
    call_block.insts.push_back(make_ret(kCaller + 12));
    caller.block_at[kCaller] = 0;
    caller.blocks.push_back(std::move(call_block));
    StructuredFunction caller_structured{
        &caller, linear_body(kCaller)};
    annotations.renames[kCaller] = "transport_caller";
    annotations.signatures[kCaller] = FunctionSig{
        .return_type = "void",
        .params = {{"int", "x"}},
        .variadic = false,
    };
    annotations.renames[kCallee] = "consume_int";
    annotations.signatures[kCallee] = FunctionSig{
        .return_type = "void",
        .params = {{"int", "value"}},
        .variadic = false,
    };
    auto call_output = emitter.emit(
        caller_structured, nullptr, &annotations, EmitOptions{});
    check(call_output.has_value() &&
              call_output->find("consume_int(x);") != std::string::npos &&
              call_output->find("consume_int((uint32_t)x);") ==
                  std::string::npos,
          "call-boundary ABI widening keeps the declared source name");
}

std::string render_stack_parameter(Format format, Arch arch, Endian endian,
                                   Reg stack_register, IrType word_type,
                                   std::size_t parameter_count,
                                   i64 offset) {
    const addr_t start = 0x7400 + static_cast<addr_t>(parameter_count * 0x10);
    IrFunction function;
    function.start = start;
    function.end = start + 12;
    function.name = "stack_parameter";
    function.next_temp_id = 2;
    const IrValue address = IrValue::make_temp(0, word_type);
    const IrValue loaded = IrValue::make_temp(1, word_type);
    IrBlock block;
    block.start = start;
    block.end = function.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        address, IrValue::make_reg(stack_register, word_type),
        IrValue::make_imm(offset, word_type)));
    block.insts.push_back(make_load(loaded, address));
    block.insts.push_back(make_ret_value(start + 8, loaded));
    function.block_at[block.start] = 0;
    function.blocks.push_back(std::move(block));
    StructuredFunction structured{
        &function, linear_body(function.start, loaded)};

    const std::string c_type = word_type == IrType::I32
        ? "uint32_t" : "uint64_t";
    FunctionSig signature;
    signature.return_type = c_type;
    for (std::size_t i = 0; i < parameter_count; ++i) {
        signature.params.push_back({
            c_type, i + 1 == parameter_count
                ? std::string{"spill"}
                : std::format("p{}", i + 1)});
    }
    Annotations annotations;
    annotations.signatures[start] = std::move(signature);
    AbiBinary binary(format, arch, endian);
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, &binary, &annotations, EmitOptions{});
    return output ? *output : std::string{};
}

void test_annotated_stack_parameters_use_abi_offsets() {
    struct Case {
        Format format;
        Arch arch;
        Endian endian;
        Reg stack_register;
        IrType word_type;
        std::size_t parameters;
        i64 offset;
    };
    constexpr std::array cases{
        Case{Format::Elf, Arch::X86_64, Endian::Little,
             Reg::Rsp, IrType::I64, 7, 0x08},
        Case{Format::RawRegions, Arch::X86_64, Endian::Little,
             Reg::Rsp, IrType::I64, 5, 0x28},
        Case{Format::Elf, Arch::Arm64, Endian::Little,
             Reg::Xsp, IrType::I64, 9, 0x00},
        Case{Format::Elf, Arch::Arm, Endian::Little,
             Reg::Asp, IrType::I32, 5, 0x00},
    };
    for (const Case& test : cases) {
        const std::string output = render_stack_parameter(
            test.format, test.arch, test.endian, test.stack_register,
            test.word_type, test.parameters, test.offset);
        check(output.find("return spill;") != std::string::npos &&
                  output.find("stack_top") == std::string::npos &&
                  output.find("arg_") == std::string::npos,
              "annotated overflow parameter resolves through its ABI stack slot");
    }
}

}  // namespace

int main() {
    test_user_variadics_names_and_zero_arity();
    test_bodyless_per_block_return_state_and_name();
    test_common_analysis_names_forwarded_argument();
    test_f32_layout_and_ipa_precedence();
    test_objc_method_metadata_precedes_block_metadata();
    test_named_integer_cast_elision_preserves_semantics();
    test_annotated_stack_parameters_use_abi_offsets();
    return fails == 0 ? 0 : 1;
}
