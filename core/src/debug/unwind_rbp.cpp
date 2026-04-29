#include <ember/debug/unwind.hpp>

#include <cstddef>
#include <cstring>

namespace ember::debug {

Result<std::vector<Frame>>
unwind_rbp(Target& t, ThreadId tid, std::size_t max_frames) {
    std::vector<Frame> out;

    auto regs = t.get_regs(tid);
    if (!regs) return std::unexpected(std::move(regs).error());

    addr_t rip = regs->rip;
    addr_t rbp = regs->rbp;
    out.push_back({rip, rbp, regs->rsp});

    while (out.size() < max_frames) {
        if (rbp == 0) break;

        std::byte buf[16] = {};
        auto n = t.read_mem(rbp, buf);
        if (!n || *n != sizeof(buf)) break;

        addr_t saved_rbp = 0;
        addr_t ret_addr  = 0;
        std::memcpy(&saved_rbp, buf,     8);
        std::memcpy(&ret_addr,  buf + 8, 8);

        if (ret_addr == 0) break;
        // Cycle / non-progressing chain — bail rather than spin forever.
        if (saved_rbp <= rbp) {
            out.push_back({ret_addr, saved_rbp, 0});
            break;
        }

        out.push_back({ret_addr, saved_rbp, 0});
        rbp = saved_rbp;
    }

    return out;
}

}  // namespace ember::debug
