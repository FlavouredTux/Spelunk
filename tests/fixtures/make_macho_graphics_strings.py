#!/usr/bin/env python3
"""Emit a tiny Mach-O with graphics API/debug strings naming stripped code."""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def align8(v):
    return align(v, 8)


def uleb128(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_graphics_strings.py <output-path>", file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    link_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    main_va = text_vmaddr
    gl_va = text_vmaddr + 6
    vk_va = gl_va + 13
    shader_va = vk_va + 13
    pack_va = shader_va + 13
    sdl_va = pack_va + 13
    metal_va = sdl_va + 13
    proc_va = metal_va + 13

    main_code = bytes.fromhex("b800000000c3")
    body_len = 7 + 5 + 1
    gl_text = b"glBindBuffer(GL_ARRAY_BUFFER, id) GL_ARB_debug_output\0"
    vk_text = b"vkCreateSwapchainKHR(device, &info, nullptr, &swapchain) VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR\0"
    shader_text = b"#version 450\nlayout(location=0) in vec3 p;\nvoid main(){gl_Position=vec4(p,1.0);}\0"
    pack_text = b"[FLog::Graphics] Loaded {} shaders from pack {} variant {} ({} bytes)\0"
    sdl_text = b"SDL_GL_GetProcAddress(\"glBindBuffer\") SDL_WINDOW_OPENGL SDL_GL_CONTEXT_PROFILE_CORE\0"
    metal_text = b"MTLCreateSystemDefaultDevice()->newRenderPipelineStateWithDescriptor(desc)\0"
    proc_names = [
        b"glActiveTexture\0",
        b"glBindBuffer\0",
        b"glBindBufferARB\0",
        b"glBufferData\0",
        b"glCompileShader\0",
        b"glCreateProgram\0",
        b"glCreateShader\0",
        b"glDrawBuffers\0",
        b"glFramebufferTexture2DEXT\0",
        b"glDebugMessageCallbackKHR\0",
        b"glObjectLabel\0",
        b"glShaderSource\0",
        b"glUniform1i\0",
        b"glUniformMatrix4fv\0",
        b"glVertexAttribPointer\0",
        b"eglGetProcAddress\0",
        b"vkCreateInstance\0",
        b"vkEnumeratePhysicalDevices\0",
        b"vkCreateDevice\0",
        b"vkGetDeviceQueue\0",
        b"vkCreateBuffer\0",
        b"vkCreateImage\0",
        b"vkCreateShaderModule\0",
        b"vkCreateGraphicsPipelines\0",
        b"vkCmdDrawIndexed\0",
        b"vkQueuePresentKHR\0",
        b"vkCreateDebugUtilsMessengerEXT\0",
        b"SDL_Vulkan_GetInstanceExtensions\0",
        b"SDL_Vulkan_CreateSurface\0",
        b"SDL_GL_CreateContext\0",
        b"SDL_GL_SetAttribute\0",
    ]

    proc_loader_len = 7 * len(proc_names) + 6
    string_off = align(len(main_code) + body_len * 6 + proc_loader_len, 8)
    gl_text_va = text_vmaddr + string_off
    vk_text_va = gl_text_va + len(gl_text)
    shader_text_va = vk_text_va + len(vk_text)
    pack_text_va = shader_text_va + len(shader_text)
    sdl_text_va = pack_text_va + len(pack_text)
    metal_text_va = sdl_text_va + len(sdl_text)
    proc_name_vas = []
    cur_string_va = metal_text_va + len(metal_text)
    for proc_name in proc_names:
        proc_name_vas.append(cur_string_va)
        cur_string_va += len(proc_name)

    def make_body(va, string_va, ret):
        disp = string_va - (va + 7)
        return b"\x48\x8d\x3d" + struct.pack("<i", disp) + bytes([0xB8, ret, 0, 0, 0, 0xC3])

    gl_code = make_body(gl_va, gl_text_va, 0x21)
    vk_code = make_body(vk_va, vk_text_va, 0x22)
    shader_code = make_body(shader_va, shader_text_va, 0x23)
    pack_code = make_body(pack_va, pack_text_va, 0x24)
    sdl_code = make_body(sdl_va, sdl_text_va, 0x25)
    metal_code = make_body(metal_va, metal_text_va, 0x26)
    proc_code = bytearray()
    for i, name_va in enumerate(proc_name_vas):
        ip = proc_va + len(proc_code)
        proc_code += b"\x48\x8d\x3d" + struct.pack("<i", name_va - (ip + 7))
    proc_code += bytes.fromhex("b827000000c3")
    code = (
        main_code + gl_code + vk_code + shader_code + pack_code +
        sdl_code + metal_code + bytes(proc_code)
    )
    cstring_size = (
        len(gl_text) + len(vk_text) + len(shader_text) + len(pack_text) +
        len(sdl_text) + len(metal_text) +
        sum(len(proc_name) for proc_name in proc_names)
    )
    text_filesize = string_off + cstring_size

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 2 * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off, text_filesize)
    seg_text += struct.pack("<IIII", 5, 5, 2, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", text_vmaddr, len(code))
    seg_text += struct.pack("<II", text_file_off, 4)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)
    seg_text += b"__cstring".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", gl_text_va, cstring_size)
    seg_text += struct.pack("<II", text_file_off + string_off, 3)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x2, 0, 0, 0)

    strings = bytearray(b"\0")
    main_name_off = len(strings)
    strings += b"_main\0"
    import_offsets = []
    for name in (
        b"_glClear\0",
        b"_glBindBufferARB\0",
        b"_eglGetProcAddress\0",
        b"_vkGetDeviceProcAddr\0",
        b"_vkCreateInstance\0",
        b"_vkQueuePresentKHR\0",
        b"_SDL_CreateWindow\0",
        b"_SDL_Vulkan_CreateSurface\0",
        b"_MTLCreateSystemDefaultDevice\0",
    ):
        import_offsets.append(len(strings))
        strings += name
    strtab = bytes(strings)
    nlists = [struct.pack("<IBBHQ", main_name_off, 0x0F, 1, 0, main_va)]
    for off in import_offsets:
        nlists.append(struct.pack("<IBBHQ", off, 0x01, 0, 0, 0))
    nlist = b"".join(nlists)

    fn_starts = (
        uleb128(gl_va - text_vmaddr) +
        uleb128(vk_va - gl_va) +
        uleb128(shader_va - vk_va) +
        uleb128(pack_va - shader_va) +
        uleb128(sdl_va - pack_va) +
        uleb128(metal_va - sdl_va) +
        uleb128(proc_va - metal_va) +
        b"\0"
    )
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    link_filesize = fn_starts_off + len(fn_starts) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", text_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, len(nlists), str_off, len(strtab))
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_link) + lc_symtab + lc_fnstarts + lc_entry
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 5, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (text_file_off + string_off - len(out))
    out += gl_text
    out += vk_text
    out += shader_text
    out += pack_text
    out += sdl_text
    out += metal_text
    for proc_name in proc_names:
        out += proc_name
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab
    out += b"\0" * (fn_starts_off - len(out))
    out += fn_starts
    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
