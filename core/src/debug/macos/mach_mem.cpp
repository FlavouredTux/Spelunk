// Memory read/write for the macOS Mach backend.
//
// `/proc/<pid>/mem`-style direct access doesn't exist; we go through
// the Mach VM API. Reads use mach_vm_read_overwrite into a caller-
// owned buffer (vs mach_vm_read which would allocate kernel-side
// storage we'd then have to vm_deallocate). Writes need a protect
// dance — text segments are typically RX, and mach_vm_write fails on
// non-writable pages — so we flip RWX, write, restore.

#include "mach_target.hpp"

#include <cerrno>
#include <cstring>
#include <format>
#include <string>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_region.h>

namespace ember::debug::mach_ {

namespace {

[[nodiscard]] Error mach_io(const char* op, kern_return_t kr) {
    return Error::io(std::format("{}: {}", op, ::mach_error_string(kr)));
}

}  // namespace

Result<std::size_t>
MachOTarget::read_mem(addr_t va, std::span<std::byte> out) {
    if (task_port_ == 0) {
        return std::unexpected(Error::io("read_mem: no task port"));
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = ::mach_vm_read_overwrite(
        task_port_,
        static_cast<mach_vm_address_t>(va),
        static_cast<mach_vm_size_t>(out.size()),
        reinterpret_cast<mach_vm_address_t>(out.data()),
        &got);
    if (kr == KERN_INVALID_ADDRESS) return std::size_t{0};   // unmapped tail
    if (kr != KERN_SUCCESS) {
        return std::unexpected(mach_io("mach_vm_read_overwrite", kr));
    }
    return static_cast<std::size_t>(got);
}

Result<std::size_t>
MachOTarget::write_mem(addr_t va, std::span<const std::byte> in) {
    if (task_port_ == 0) {
        return std::unexpected(Error::io("write_mem: no task port"));
    }
    if (in.empty()) return std::size_t{0};

    const auto vaddr = static_cast<mach_vm_address_t>(va);
    const auto sz    = static_cast<mach_vm_size_t>(in.size());

    // Snapshot original protection so we can restore after the write.
    // mach_vm_region returns the bits for the region containing vaddr;
    // a multi-page write spanning regions with different prot would
    // need a per-page loop, but in practice bp patches are 1 byte.
    mach_vm_address_t qaddr = vaddr;
    mach_vm_size_t    qsize = 0;
    vm_region_basic_info_data_64_t info{};
    mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kq = ::mach_vm_region(
        task_port_, &qaddr, &qsize,
        VM_REGION_BASIC_INFO_64,
        reinterpret_cast<vm_region_info_t>(&info),
        &info_cnt, &object_name);
    if (kq != KERN_SUCCESS) {
        return std::unexpected(mach_io("mach_vm_region", kq));
    }
    const vm_prot_t orig_prot = info.protection;

    // Bump to RW with COPY semantics so shared-text pages get a private
    // CoW copy in the tracee — exactly what gdb/lldb do for int3
    // patches. Without VM_PROT_COPY a write to shared text would fail.
    kern_return_t kp = ::mach_vm_protect(
        task_port_, vaddr, sz, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kp != KERN_SUCCESS) {
        return std::unexpected(mach_io("mach_vm_protect (RWX)", kp));
    }

    kern_return_t kw = ::mach_vm_write(
        task_port_, vaddr,
        reinterpret_cast<vm_offset_t>(in.data()),
        static_cast<mach_msg_type_number_t>(sz));

    // Best-effort restore. A failure here leaves the page wider than
    // it was — undesirable but not a correctness bug for the debugger.
    ::mach_vm_protect(task_port_, vaddr, sz, FALSE, orig_prot);

    if (kw == KERN_INVALID_ADDRESS) return std::size_t{0};
    if (kw != KERN_SUCCESS) {
        return std::unexpected(mach_io("mach_vm_write", kw));
    }
    return in.size();
}

}  // namespace ember::debug::mach_
