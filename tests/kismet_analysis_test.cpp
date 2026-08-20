#include <ember/analysis/kismet.hpp>

#include <cassert>
#include <string>
#include <utility>
#include <vector>

int main() {
    const std::string disassembly = R"KISMET(Label_0x0:
     $7: Jump to offset 0x20 if not expr:
       $1: Instance variable of type bool named Enabled?.
Label_0x10:
     $F: Let (Variable = Expression)
       Variable:
         $1: Instance variable of type double named Alpha.
       Expression:
         $37: literal double 1.000000
Label_0x20:
     $4: Return expression
       $B: EX_Nothing
Label_0x22:
     $53: EX_EndOfScript
)KISMET";

    auto cfg = ember::parse_kismet_cfg(disassembly);
    assert(cfg);
    assert(cfg->blocks.size() == 4);
    assert(cfg->blocks[0].successors.size() == 2);
    assert(cfg->blocks[0].successors[0] == 0x20);
    assert(cfg->blocks[0].successors[1] == 0x10);

    const std::string cfg_text = ember::emit_kismet_cfg(*cfg);
    assert(cfg_text.find("block 0x0 -> 0x20 0x10") != std::string::npos);

    const std::string pseudo = ember::emit_kismet_pseudocode(*cfg, "BP_Test_C:Run");
    assert(pseudo.find("void Run()") != std::string::npos);
    assert(pseudo.find("if (!(this->Enabled)) goto label_20;") != std::string::npos);
    assert(pseudo.find("this->Alpha = 1.000000;") != std::string::npos);

    const std::vector<std::pair<std::string, std::string>> wrappers = {
        {"/Game/BP_Test.BP_Test_C:ReceiveBeginPlay",
         "Label_0x0:\n"
         "  $46: Local Final Script Function (stack node BP_Test_C::ExecuteUbergraph_BP_Test)\n"
         "    $1D: literal int32 32\n"
         "    $16: EX_EndFunctionParms\n"},
        {"/Game/BP_Test.BP_Test_C:ExecuteUbergraph_BP_Test", disassembly},
    };
    const auto entries = ember::discover_kismet_ubergraph_entries(
        "ExecuteUbergraph_BP_Test", wrappers);
    assert(entries.size() == 1);
    assert(entries[0].offset == 32);
    assert(entries[0].wrapper_function.ends_with("ReceiveBeginPlay"));

    const std::string flow_disassembly = R"KISMET(Label_0x0:
     $4C: FlowStack.Push(0x20);
Label_0x5:
     $4F: if (!condition) { if (FlowStack.Num()) { jump to statement at FlowStack.Pop(); } else { ERROR!!! } }
       $1: Instance variable of type bool named KeepGoing?.
Label_0x10:
     $4D: if (FlowStack.Num()) { jump to statement at FlowStack.Pop(); } else { ERROR!!! }
Label_0x20:
     $4: Return expression
       $B: EX_Nothing
)KISMET";
    auto flow_cfg = ember::parse_kismet_cfg(flow_disassembly);
    assert(flow_cfg && flow_cfg->blocks.size() == 4);
    assert(flow_cfg->blocks[0].successors.size() == 1);
    assert(flow_cfg->blocks[0].successors[0] == 0x5);
    assert(flow_cfg->blocks[1].successors.size() == 2);
    assert(flow_cfg->blocks[1].successors[0] == 0x20);
    assert(flow_cfg->blocks[1].successors[1] == 0x10);
    assert(flow_cfg->blocks[2].successors.size() == 1);
    assert(flow_cfg->blocks[2].successors[0] == 0x20);
}
