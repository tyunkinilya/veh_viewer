import os
import idc
import idautils
import ida_bytes

from ida_idd import Appcall
from ida_kernwin import Choose
from ida_ida import inf_get_max_ea
from idaapi import get_inf_structure


proc_info = get_inf_structure()

if proc_info.is_32bit():
    idc.parse_decls("""struct _VECTORED_HANDLER_ENTRY {
    _VECTORED_HANDLER_ENTRY* next;
    _VECTORED_HANDLER_ENTRY* previous;
    _DWORD refs;
    _DWORD reserved;
    PVECTORED_EXCEPTION_HANDLER handler;
    };

    struct _VECTORED_HANDLER_LIST {
    void* mutex_exception;
    _VECTORED_HANDLER_ENTRY* first_exception_handler;
    _VECTORED_HANDLER_ENTRY* last_exception_handler;
    void* mutex_continue;
    _VECTORED_HANDLER_ENTRY* first_continue_handler;
    _VECTORED_HANDLER_ENTRY* last_continue_handler;
    };""", 0)

if proc_info.is_64bit():
    idc.parse_decls("""struct _VECTORED_HANDLER_ENTRY {
    _VECTORED_HANDLER_ENTRY* next;
    _VECTORED_HANDLER_ENTRY* previous;
    _QWORD refs;
    _QWORD reserved;
    PVECTORED_EXCEPTION_HANDLER handler;
    };

    struct _VECTORED_HANDLER_LIST {
    void* mutex_exception;
    _VECTORED_HANDLER_ENTRY* first_exception_handler;
    _VECTORED_HANDLER_ENTRY* last_exception_handler;
    void* mutex_continue;
    _VECTORED_HANDLER_ENTRY* first_continue_handler;
    _VECTORED_HANDLER_ENTRY* last_continue_handler;
    };""", 0)

WORD_SIZE = 0
if proc_info.is_32bit():
    WORD_SIZE = 4
if proc_info.is_64bit():
    WORD_SIZE = 8

def read_value(ea):
    if proc_info.is_64bit():
        return idc.get_qword(ea), ea + 8
    if proc_info.is_32bit():
        return idc.get_wide_dword(ea), ea + 4


def format_hex(x):
    if proc_info.is_64bit():
        return format(x, "016X")
    if proc_info.is_32bit():
        return format(x, "08X")


class VECTORED_HANDLER_ENTRY:
    next = 0
    previous = 0
    refs = 0
    reserved = 0
    handler = 0

    def __init__(self, ea):
        self.from_mem(ea)

    def from_mem(self, ea):
        self.next, ea = read_value(ea)
        self.previous, ea = read_value(ea)
        self.refs, ea = read_value(ea)
        self.reserved, ea = read_value(ea)
        self.handler, ea = read_value(ea)


class VECTORED_HANDLER_LIST:
    mutex_exception = 0
    first_exception_handler = 0
    last_exception_handler = 0
    mutex_continue = 0
    first_continue_handler = 0
    last_continue_handler = 0

    def __init__(self, ea):
        self.from_mem(ea)

    def from_mem(self, ea):
        self.mutex_exception, ea = read_value(ea)
        self.first_exception_handler, ea = read_value(ea)
        self.last_exception_handler, ea = read_value(ea)
        self.mutex_continue, ea = read_value(ea)
        self.first_continue_handler, ea = read_value(ea)
        self.last_continue_handler, ea = read_value(ea)


def fix_pe_sections(pe):
    for section in pe.sections:
        section.PointerToRawData = section.VirtualAddress


def load_pe_from_mem(data):
    pe = pefile.PE(data=data, fast_load=True)
    fix_pe_sections(pe)
    pe.full_load()
    return pe


def GetProcAddress(pe, base_address, name):
    if pe == None:
        return None
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if symbol.name.lower() == name.lower().encode():
            return symbol.address + base_address
    return None


def find_insn(ea, insn_name, e_count=500):
    for _ in range(e_count):
        if idc.print_insn_mnem(ea) == insn_name:
            return ea
        ea = idc.next_head(ea)
    return 0


def find_bin_mask(mask, start, end=idc.BADADDR):
    patterns = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(
        patterns,
        idc.INF_BASEADDR,
        mask,
        16)

    if err:
        print("Bad pattern mask")
        return 0
    ea = ida_bytes.bin_search(
        start,
        inf_get_max_ea() if end == idc.BADADDR else end + 1,
        patterns,
        ida_bytes.BIN_SEARCH_FORWARD
        | ida_bytes.BIN_SEARCH_NOBREAK
        | ida_bytes.BIN_SEARCH_NOSHOW)
    if ea == idc.BADADDR:
        return 0
    return ea

def VHL_generic_search(func_start, ntdll_base):
    mem_pointers = set()

    for start, end in idautils.Chunks(func_start):
        ea = start
        while ea < end:
            for i in range(20):
                if idc.print_operand(ea, i) == '':
                    break
                if idc.get_operand_type(ea, i) in [idc.o_mem, idc.o_imm, idc.o_far]:
                    value = idc.get_operand_value(ea, i)
                    if value > ntdll_base and idc.is_loaded(value):
                        print(f"{format_hex(ea)} -> {format_hex(value)}")
                        mem_pointers.add(value)
            ea = idc.next_head(ea)
    mem_pointers = list(mem_pointers)
    for mem_pointer in mem_pointers:
        only_pointers = True
        for i in range(6):
            value, _ = read_value(mem_pointer + i*WORD_SIZE)
            # print(f"{mem_pointer:08X}[{i}] -> {value:08X}, {idc.is_loaded(value)}")
            only_pointers = only_pointers and idc.is_loaded(value)
        if only_pointers:
            return mem_pointer
    return idc.BADADDR


ntdll_base = 0
ntdll_size = 0
ntdll_pe = None
for module in idautils.Modules():
    module_name = os.path.basename(module.name.lower())
    if module_name == 'ntdll.dll' or module_name == 'ntdll':
        ntdll_base = module.base
        ntdll_size = module.size
        print(f"{format_hex(ntdll_base)} -> {module_name}")

p_RtlDecodePointer = idc.get_name_ea(ntdll_base, "ntdll_RtlDecodePointer")
p_RtlAddVectoredExceptionHandler = idc.get_name_ea(ntdll_base, "ntdll_RtlAddVectoredExceptionHandler")

if p_RtlAddVectoredExceptionHandler == idc.BADADDR or p_RtlDecodePointer == idc.BADADDR:
    import pefile
    ntdll_pe = load_pe_from_mem(ida_bytes.get_bytes(ntdll_base, ntdll_size))

    p_RtlDecodePointer = GetProcAddress(ntdll_pe, ntdll_base, "RtlDecodePointer")
    idc.set_name(p_RtlDecodePointer, "")
    idc.set_name(p_RtlDecodePointer, "ntdll_RtlDecodePointer")

    p_RtlAddVectoredExceptionHandler = GetProcAddress(ntdll_pe, ntdll_base, "RtlAddVectoredExceptionHandler")
    idc.add_func(p_RtlAddVectoredExceptionHandler, idc.find_func_end(p_RtlAddVectoredExceptionHandler))


RtlDecodePointer = Appcall.proto("ntdll_RtlDecodePointer", "PVOID __stdcall RtlDecodePointer(PVOID Ptr);")

LdrpVectorHandlerList = 0

if proc_info.is_32bit():
    idc.add_func(p_RtlAddVectoredExceptionHandler, idc.find_func_end(p_RtlAddVectoredExceptionHandler))
    call_ea = find_insn(p_RtlAddVectoredExceptionHandler, 'call')
    p_RtlAddVectoredExceptionHandlerImpl = idc.get_operand_value(call_ea, 0)
    idc.add_func(p_RtlAddVectoredExceptionHandlerImpl, idc.find_func_end(p_RtlAddVectoredExceptionHandlerImpl))
    '''
    89 46 10                mov     [esi+10h], eax
    81 C3 3C 93 3A 77       add     ebx, offset LdrpVectorHandlerList
    '''
    start = p_RtlAddVectoredExceptionHandlerImpl
    end = idc.find_func_end(start)
    p_insns = find_bin_mask("89 46 10 81 C3 ?? ?? ?? ??", start, end)
    if p_insns != 0:
        p_insns = idc.next_head(p_insns)
        LdrpVectorHandlerList = idc.get_operand_value(p_insns, 1)
    else:
        print("Can't find by mask, trying generic search.")
        LdrpVectorHandlerList = VHL_generic_search(p_RtlAddVectoredExceptionHandlerImpl, ntdll_base)
        if LdrpVectorHandlerList == idc.BADADDR:
            print("Genric search failed. Find VectorHandlerList manually an set its name as 'LdrpVectorHandlerList'")

if proc_info.is_64bit():
    '''
    48 8D 0D 2E DC 0F 00          lea     rcx, LdrpVectorHandlerList
    48 8B 0C F1                   mov     rcx, [rcx+rsi*8]

    48 8D 05 E4 DB 0F 00          lea     rax, LdrpVectorHandlerList
    48 8B 0C F0                   mov     rcx, [rax+rsi*8]
    '''
    start = p_RtlAddVectoredExceptionHandler
    end = idc.find_func_end(start)
    idc.add_func(start, end)
    p_insns = find_bin_mask("48 8D ?? ?? ?? ?? ?? 48 8B 0C ??", start, end)
    if p_insns != 0:
        LdrpVectorHandlerList = idc.get_operand_value(p_insns, 1)
    else:
        print("Can't find by mask, trying generic search.")
        LdrpVectorHandlerList = VHL_generic_search(p_RtlAddVectoredExceptionHandlerImpl, ntdll_base)
        if LdrpVectorHandlerList == idc.BADADDR:
            print("Genric search failed. Find VectorHandlerList manually an set its name as 'LdrpVectorHandlerList'")


idc.set_name(LdrpVectorHandlerList, "")
idc.set_name(LdrpVectorHandlerList, "LdrpVectorHandlerList")
idc.apply_type(LdrpVectorHandlerList, idc.parse_decl(
    "_VECTORED_HANDLER_LIST LdrpVectorHandlerList;", idc.PT_SILENT))
print(f"LdrpVectorHandlerList = {format_hex(LdrpVectorHandlerList)}")

class VehChoose(Choose):

    def __init__(self, title):
        Choose.__init__(
            self,
            title,
            [["Address",  10 | Choose.CHCOL_HEX],
             ["Name",     30 | Choose.CHCOL_PLAIN],
             ["Position", 10 | Choose.CHCOL_DEC]])
        self.items = []
        self.icon = 41

    def OnInit(self):
        self.items = []

        p_LdrpVectorHandlerList = idc.get_name_ea(0, "LdrpVectorHandlerList")
        LdrpVectorHandlerList = VECTORED_HANDLER_LIST(p_LdrpVectorHandlerList)
        first_exception_handler = LdrpVectorHandlerList.first_exception_handler

        if first_exception_handler == p_LdrpVectorHandlerList + WORD_SIZE:
            print("No exception handlers")
            return True

        last_exception_handler = LdrpVectorHandlerList.last_exception_handler
        p_exception_handler = first_exception_handler
        # idc.apply_type(p_exception_handler, idc.parse_decl(
        #     f"_VECTORED_HANDLER_ENTRY VEH_ENTRY_{format_hex(p_exception_handler)};", idc.PT_SILENT))

        exception_handler = VECTORED_HANDLER_ENTRY(p_exception_handler)

        handler = RtlDecodePointer(exception_handler.handler)
        if isinstance(handler, int) == False:
            handler = handler.value

        if idc.is_loaded(handler) == False:
            handler = RtlDecodePointer(exception_handler.reserved)
            if isinstance(handler, int) == False:
                handler = handler.value

        idc.set_name(handler, f"VEH_{format_hex(handler)}")
        idc.add_func(handler, idc.find_func_end(handler))
        idc.apply_type(handler, idc.parse_decl(
            f"LONG VEH_{format_hex(handler)}(_EXCEPTION_POINTERS *ExceptionInfo)", idc.PT_SILENT))
        self.items.append([f"{format_hex(handler)}", idc.get_func_name(
            handler), str(len(self.items) + 1), handler])

        while p_exception_handler != last_exception_handler:
            p_exception_handler = exception_handler.next
            # idc.apply_type(p_exception_handler, idc.parse_decl(
            #     f"_VECTORED_HANDLER_ENTRY VEH_ENTRY_{format_hex(p_exception_handler)};", idc.PT_SILENT))

            exception_handler = VECTORED_HANDLER_ENTRY(p_exception_handler)
            handler = RtlDecodePointer(exception_handler.handler)
            if isinstance(handler, int) == False:
                handler = handler.value
            idc.set_name(handler, f"VEH_{format_hex(handler)}")
            idc.add_func(handler, idc.find_func_end(handler))
            idc.apply_type(handler, idc.parse_decl(
                f"LONG VEH_{format_hex(handler)}(_EXCEPTION_POINTERS *ExceptionInfo)", idc.PT_SILENT))
            self.items.append([f"{format_hex(handler)}", idc.get_func_name(
                handler), str(len(self.items) + 1), handler])
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        idc.jumpto(self.items[n][3])
        return (Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self.OnInit()
        # try to preserve the cursor
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)


c = VehChoose("VEH List")
c.Show()
