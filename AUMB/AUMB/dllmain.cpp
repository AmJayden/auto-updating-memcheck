#include <Windows.h>
#include <thread>
#include <cinttypes>
#include <map>
#include <array>

#include "utils/utils.hpp"

#include <Zydis/Zydis.h>

#pragma comment(lib, "Zydis.lib")

inline const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));

inline std::uintptr_t memcheck_core = 0;
inline std::uintptr_t hasher_end = 0;

__declspec(naked) std::uintptr_t stub()
{
    static std::uintptr_t to_spoof;
    __asm
    {
        mov edx, 0x00000000
        mov edx, esp
        pop edx

        mov ebx, [ebp - 0x10]
        mov to_spoof, ebx
    }

    to_spoof = utils::spoof(to_spoof);

    __asm
    {
        mov ecx, [ebp - 0x48]
        mov esi, [ebp - 0x18]
        mov edi, [ebp - 0x24]

        mov eax, to_spoof
        mov[esp], eax

        hasher_begin:
        mov eax, [esp]
        mov eax, [eax]
        add eax, ebx
        imul eax, eax, 0x1594FE2D
        add eax, edi
        rol eax, 0x13
        imul edi, eax, 0xCBB4ABF7

        lea eax, [ebx + 4]

        push eax
        mov eax, [esp + 0x4]
        mov eax, [eax + 0x4]
        sub[esp], eax
        pop eax

        add ebx, 0x8
        add DWORD PTR[esp], 0x08

        imul eax, eax, 0x344B5409
        add eax, [ebp - 0x20]
        rol eax, 0x11
        imul eax, eax, 0x1594FE2D
        mov[ebp - 0x20], eax

        mov eax, [esp]
        mov eax, [eax]
        xor eax, ebx
        add ebx, 0x04
        add DWORD PTR[esp], 0x04
        imul eax, eax, 0x1594FE2D
        add eax, [ebp - 0x1C]
        rol eax, 0x0D
        imul eax, eax, 0xCBB4ABF7
        mov[ebp - 0x1C], eax

        mov eax, [esp]
        mov eax, [eax]
        sub eax, ebx
        add ebx, 0x04
        add DWORD PTR[esp], 0x04
        imul eax, eax, 0x344B5409
        add eax, esi
        rol eax, 0x0F
        imul esi, eax, 0x1594FE2D
        cmp ebx, ecx
        jb hasher_begin

        mov esp, [esp + 0x08]
        jmp[hasher_end]
    }

}

void main_d()
{
    utils::hook_free_console();

    AllocConsole();

    FILE* file_stream;

    freopen_s(&file_stream, "CONIN$", "r", stdin);
    freopen_s(&file_stream, "CONOUT$", "w", stdout);
    freopen_s(&file_stream, "CONOUT$", "w", stderr);

    SetConsoleTitleA("AUMB");

    std::printf("[AUMB] Started!\n\n");

    memcheck_core = utils::pattern_scan("\x8B\xD4\x5A\x8B\x64\x24\x08\x8B\x5D\xF0", "xxxxxxxxxx").back() - 5;
    hasher_end = memcheck_core + 0x8C;

    std::printf("[AUMB] Main Hasher: 0x%X\n", memcheck_core);

    const auto stub_addy = reinterpret_cast<std::uintptr_t>(&stub);

    DWORD old{};

    VirtualProtect(reinterpret_cast<void*>(stub_addy), 5, PAGE_EXECUTE_READWRITE, &old);

    *reinterpret_cast<std::uintptr_t*>(stub_addy + 1) = *reinterpret_cast<std::uintptr_t*>(memcheck_core + 1);

    VirtualProtect(reinterpret_cast<void*>(stub_addy), 5, old, &old);

    std::vector<std::uintptr_t> silent_checkers;

    for (const auto vec = utils::pattern_scan("\x3B\x00\x73\x00\x2B\x00\x8D\x00\x02", "x?x?x?x?x"); const auto sc : vec)
        silent_checkers.push_back(utils::get_prologue(sc));

    for (const auto vec = utils::pattern_scan("\x3B\x00\x0F\x00\x00\x00\x00\x00\x2B\x00\x8D\x00\x02", "x?x?????x?x?x"); const auto sc : vec)
        silent_checkers.push_back(utils::get_prologue(sc));

    utils::text_clone = utils::clone_section(utils::text_seg.start_addr);
    utils::vmp0_clone = utils::clone_section(utils::vmp0_seg.start_addr);

    std::printf("\n[AUMB] .text Clone: 0x%X\n", utils::text_clone);
    std::printf("[AUMB] .vmp0 Clone: 0x%X\n\n", utils::vmp0_clone);

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    for (const auto silent_checker : silent_checkers)
    {
        auto spoofed_checker = reinterpret_cast<std::uintptr_t>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!spoofed_checker)
            return;

        ZyanU32 runtime_address = silent_checker;
        ZyanUSize offset = 0;
        ZyanUSize clone_offset = 0;
        ZydisDecodedInstruction instruction;

        const auto size = utils::calculate_function_size(silent_checker);

        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, reinterpret_cast<void*>(silent_checker + offset), size - offset, &instruction)))
        {
            char buffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);

            static const std::map<ZydisRegister, std::array<std::uint8_t, 16>> shellcode_map
            {
				{ ZYDIS_REGISTER_ECX, { 0x50, 0x51, 0x52, 0x56, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x5A, 0x59, 0x8B, 0xC8, 0x58 } },
                { ZYDIS_REGISTER_EDX, { 0x50, 0x51, 0x52, 0x56, 0x52, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x5A, 0x59, 0x8B, 0xD0, 0x58 } },
				{ ZYDIS_REGISTER_EAX, { 0x90, 0x51, 0x52, 0x56, 0x50, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x5A, 0x59, 0x90, 0x90, 0x90 } },
                { ZYDIS_REGISTER_EDI, { 0x50, 0x51, 0x52, 0x56, 0x57, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x5A, 0x59, 0x8B, 0xF8, 0x58 } },
            };

            if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operands[0].mem.base == ZYDIS_REGISTER_EBP && (instruction.operands[0].mem.disp.value == 0xC || instruction.operands[0].mem.disp.value == 0x8) && offset <= 0x30)
            {
                std::printf("[AUMB] %08X %s\n", runtime_address, buffer);

                std::uint8_t spoof[16]{};

                if (auto it = shellcode_map.find(instruction.operands[1].reg.value); it != shellcode_map.end())
                    std::memcpy(spoof, it->second.data(), sizeof(it->second));

                std::memcpy(reinterpret_cast<void*>(spoofed_checker + clone_offset), spoof, sizeof(spoof));

                *reinterpret_cast<std::uintptr_t*>(spoofed_checker + clone_offset + 6) = reinterpret_cast<std::uintptr_t>(utils::spoof) - (spoofed_checker + clone_offset + 6) - 4;

                clone_offset += sizeof(spoof);
            }

            for (auto i = 0u; i < instruction.length; ++i)
                *reinterpret_cast<std::uint8_t*>(spoofed_checker + clone_offset + i) = *reinterpret_cast<std::uint8_t*>(runtime_address + i);

            clone_offset += instruction.length;
            offset += instruction.length;
            runtime_address += instruction.length;
        }

        DWORD old_protect{};

        VirtualProtect(reinterpret_cast<void*>(silent_checker), 5, PAGE_EXECUTE_READWRITE, &old_protect);

        std::memset(reinterpret_cast<void*>(silent_checker), 0x90, 5);

        *reinterpret_cast<std::uint8_t*>(silent_checker) = 0xE9;
        *reinterpret_cast<std::uintptr_t*>(silent_checker + 1) = (spoofed_checker - silent_checker - 5);

        VirtualProtect(reinterpret_cast<void*>(silent_checker), 5, old_protect, &old_protect);
    }

    std::printf("\n[AUMB] Spoof Function: 0x%p\n", utils::spoof);

    DWORD old_protect{};

    VirtualProtect(reinterpret_cast<void*>(memcheck_core), 5, 0x40, &old_protect);

    const auto rel_location = (reinterpret_cast<std::uintptr_t>(stub) - memcheck_core - 5);
    *reinterpret_cast<std::uint8_t*>(memcheck_core) = 0xE9;
    *reinterpret_cast<uintptr_t*>(memcheck_core + 1) = rel_location;

    VirtualProtect(reinterpret_cast<void*>(memcheck_core), 5, old_protect, &old_protect);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        std::thread{ main_d }.detach();

    return TRUE;
}