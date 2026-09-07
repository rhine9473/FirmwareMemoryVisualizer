"""
Firmware Memory Visualizer - Parser Engine
Supports ELF/AXF binary files and Keil/GCC/TI Linker Map files.
Supports internal SRAM and external PSRAM/SDRAM split detection.
Accurate LMA/VMA tracking, non-destructive capacity detection, and robust multi-line map parsing.
"""

import os
import re
from typing import Dict, List, Any, Optional, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import SH_FLAGS
    from elftools.elf.sections import SymbolTableSection
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False


def format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    else:
        return f"{size / (1024 * 1024):.2f} MB"


def is_external_ram_section(sec_name: str, addr: int) -> bool:
    """Determine if a section belongs to external RAM (PSRAM, SDRAM)."""
    name_l = sec_name.lower()
    if any(k in name_l for k in ['ext_ram', 'psram', 'sdram', 'extram', '.ext_']):
        return True
    # STM32 FMC / FSMC external memory space (0x60000000 ~ 0xDFFFFFFF)
    if 0x60000000 <= addr < 0xE0000000 and not (0x600fffe8 <= addr <= 0x600fffff):
        return True
    # ESP32 PSRAM mapped address spaces (excluding flash DROM)
    if (0x3C000000 <= addr < 0x3E000000) or (0x48000000 <= addr < 0x4C000000):
        if 'flash' not in name_l and 'rodata' not in name_l:
            return True
    return False


def is_internal_ram_address(addr: int, sec_name: str = "") -> bool:
    """Check if address is within common internal SRAM ranges."""
    name_l = sec_name.lower()
    if is_external_ram_section(sec_name, addr):
        return False
    # Standard ARM Cortex-M internal SRAM: 0x20000000 ~ 0x3FFFFFFF
    if 0x20000000 <= addr < 0x40000000:
        return True
    # ESP32-P4 HP SRAM: 0x4FF00000 ~ 0x4FFFFFFF, TCM: 0x30100000 ~ 0x30200000
    if 0x4FF00000 <= addr < 0x50000000 or 0x30100000 <= addr < 0x30200000:
        return True
    # ESP32 RTC memory
    if 0x50000000 <= addr < 0x50110000 or 0x600fffe8 <= addr <= 0x600fffff:
        return True
    # Specific section names
    if any(k in name_l for k in ['dram', 'iram', 'bss', 'stack', 'heap', 'sdata', 'sbss']):
        return True
    return False


def is_debug_or_metadata(sec_name: str, addr: int) -> bool:
    """Check if a section is purely host debug info or build metadata."""
    name_l = sec_name.lower()
    if addr == 0 and (
        name_l.startswith('.debug') or
        name_l.startswith('.comment') or
        name_l.startswith('.arm.attributes') or
        name_l.startswith('.riscv.attributes') or
        name_l.startswith('.ti.section.flags') or
        name_l.startswith('.symtab_meta')
    ):
        return True
    return False


ESP_CHIP_SPECS = {
    'ESP32S3': {'name': 'ESP32-S3', 'physical_ram_kb': 512, 'default_usable_ram_kb': 333},
    'ESP32': {'name': 'ESP32', 'physical_ram_kb': 520, 'default_usable_ram_kb': 320},
    'ESP32S2': {'name': 'ESP32-S2', 'physical_ram_kb': 320, 'default_usable_ram_kb': 240},
    'ESP32C3': {'name': 'ESP32-C3', 'physical_ram_kb': 400, 'default_usable_ram_kb': 326},
    'ESP32C6': {'name': 'ESP32-C6', 'physical_ram_kb': 512, 'default_usable_ram_kb': 416},
    'ESP32H2': {'name': 'ESP32-H2', 'physical_ram_kb': 320, 'default_usable_ram_kb': 240},
    'ESP32C2': {'name': 'ESP32-C2', 'physical_ram_kb': 272, 'default_usable_ram_kb': 200},
    'ESP32P4': {'name': 'ESP32-P4', 'physical_ram_kb': 768, 'default_usable_ram_kb': 670},
}


def detect_chip_limits(file_path: str, flash_used: int, ram_int_used: int, ram_ext_used: int,
                       esp_target: Optional[str] = None, map_caps: Optional[Dict[str, int]] = None) -> Tuple[int, int, int, bool, str, str]:
    """
    Auto-detect physical Flash, Internal RAM, and External RAM upper limits in KB.
    Crucial fix: Never artificially enlarge a confirmed chip capacity to hide overflows!
    Returns: (flash_cap_kb, ram_int_cap_kb, ram_ext_cap_kb, has_ext_ram, ext_ram_name, ram_int_note)
    """
    flash_cap = None
    ram_int_cap = None
    ram_ext_cap = None
    has_ext_ram = False
    ext_ram_name = ""
    ram_int_note = ""

    # Priority 0: Capacities extracted directly from Linker Map's Memory Configuration
    if map_caps:
        if map_caps.get('flash'):
            flash_cap = map_caps['flash']
        if map_caps.get('ram_int'):
            ram_int_cap = map_caps['ram_int']
        if map_caps.get('ram_ext'):
            ram_ext_cap = map_caps['ram_ext']
            has_ext_ram = True

    if ram_ext_used > 0:
        has_ext_ram = True
        if not ext_ram_name:
            ext_ram_name = "外部扩展 RAM"

    dir_path = os.path.dirname(os.path.abspath(file_path))
    parent_dir = os.path.dirname(dir_path)
    base_no_ext = os.path.splitext(file_path)[0]

    norm_target = esp_target.upper().replace('-', '').replace('_', '') if esp_target else None

    # Check project_description.json / flasher_args.json for target
    for d in [dir_path, parent_dir]:
        desc_file = os.path.join(d, 'project_description.json')
        if not norm_target and os.path.exists(desc_file):
            try:
                import json
                with open(desc_file, 'r', encoding='utf-8') as f:
                    j = json.load(f)
                    t = j.get('target', '')
                    if t:
                        norm_target = t.upper().replace('-', '').replace('_', '')
            except Exception:
                pass

    # 1. Check ESP-IDF sdkconfig / project files
    for d in [dir_path, parent_dir, os.path.dirname(parent_dir)]:
        sdk_file = os.path.join(d, 'sdkconfig')
        if os.path.exists(sdk_file):
            try:
                with open(sdk_file, 'r', encoding='utf-8', errors='ignore') as f:
                    sdk_txt = f.read()

                    # Flash Size
                    if not flash_cap:
                        m_f = re.search(r'CONFIG_ESPTOOLPY_FLASHSIZE_([0-9]+)MB=y', sdk_txt)
                        if m_f:
                            flash_cap = int(m_f.group(1)) * 1024
                        else:
                            m_f2 = re.search(r'CONFIG_ESPTOOLPY_FLASHSIZE="([0-9]+)MB"', sdk_txt)
                            if m_f2:
                                flash_cap = int(m_f2.group(1)) * 1024

                    # External PSRAM Detection
                    if 'CONFIG_SPIRAM=y' in sdk_txt:
                        has_ext_ram = True
                        if 'CONFIG_SPIRAM_MODE_OCT=y' in sdk_txt:
                            ext_ram_name = "8MB Octal PSRAM (OPI)"
                            ram_ext_cap = 8 * 1024
                        elif 'CONFIG_SPIRAM_MODE_HEX=y' in sdk_txt:
                            ext_ram_name = "16MB Hexa PSRAM (ESP32-P4)"
                            ram_ext_cap = 16 * 1024
                        elif 'CONFIG_SPIRAM_TYPE_ESPPSRAM64=y' in sdk_txt:
                            ext_ram_name = "8MB PSRAM (ESPPSRAM64)"
                            ram_ext_cap = 8 * 1024
                        elif ram_ext_used > 8 * 1024 * 1024:
                            ext_ram_name = "16MB PSRAM"
                            ram_ext_cap = 16 * 1024
                        elif ram_ext_used > 4 * 1024 * 1024:
                            ext_ram_name = "8MB PSRAM"
                            ram_ext_cap = 8 * 1024
                        else:
                            ext_ram_name = "4MB PSRAM"
                            ram_ext_cap = 4 * 1024
            except Exception:
                pass
            break

    # 2. Check sibling .map file if not already detected
    map_dram_usable_kb = None
    map_candidates = [base_no_ext + '.map', os.path.join(dir_path, os.path.basename(base_no_ext) + '.map')]
    for map_f in map_candidates:
        if os.path.exists(map_f) and os.path.abspath(map_f) != os.path.abspath(file_path):
            try:
                with open(map_f, 'r', encoding='utf-8', errors='ignore') as f:
                    map_txt = f.read()

                    if not norm_target:
                        m_t = re.search(r'IDF_TARGET_([a-zA-Z0-9]+)\s*=', map_txt)
                        if m_t:
                            norm_target = m_t.group(1).upper().replace('-', '').replace('_', '')

                    if "extern_ram_seg" in map_txt or "sdram" in map_txt.lower():
                        has_ext_ram = True
                        if not ext_ram_name:
                            ext_ram_name = "外扩 SDRAM / PSRAM"

                    if "Memory Configuration" in map_txt:
                        m_dram = re.search(r'dram0_0_seg\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)', map_txt)
                        if m_dram:
                            map_dram_usable_kb = int(m_dram.group(1), 16) // 1024

                        for m_m in re.finditer(r'^\s*([a-zA-Z0-9_]+)\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)', map_txt, re.MULTILINE):
                            r_name = m_m.group(1).lower()
                            r_len = int(m_m.group(2), 16) // 1024
                            if 0 < r_len < 1024 * 1024:
                                if ('flash' in r_name or 'irom' in r_name or 'rom' in r_name) and not flash_cap:
                                    flash_cap = r_len
                                if ('sram' in r_name or 'dram' in r_name) and 'tcm' not in r_name and not ram_int_cap:
                                    ram_int_cap = r_len
                                if ('extern_ram' in r_name or 'sdram' in r_name) and not ram_ext_cap:
                                    ram_ext_cap = r_len

                    if "Execution Region IROM" in map_txt and not flash_cap:
                        m_k_rom = re.search(r'Execution Region IROM\d+.*Max:\s*(0x[0-9a-fA-F]+)', map_txt)
                        if m_k_rom:
                            flash_cap = int(m_k_rom.group(1), 16) // 1024
                    if "Execution Region IRAM" in map_txt and not ram_int_cap:
                        m_k_ram = re.search(r'Execution Region IRAM\d+.*Max:\s*(0x[0-9a-fA-F]+)', map_txt)
                        if m_k_ram:
                            ram_int_cap = int(m_k_ram.group(1), 16) // 1024
                    if "Execution Region ER_SDRAM" in map_txt or "Execution Region EX_RAM" in map_txt:
                        has_ext_ram = True
                        if not ext_ram_name:
                            ext_ram_name = "外部 SDRAM"
            except Exception:
                pass

    # 3. Check Chip Name Database from full path
    full_path_upper = file_path.upper().replace('\\', '/')
    if not norm_target:
        for t_key in ESP_CHIP_SPECS:
            if t_key in full_path_upper.replace('-', '').replace('_', ''):
                norm_target = t_key
                break

    # If ESP32 chip family
    if norm_target and norm_target in ESP_CHIP_SPECS:
        spec = ESP_CHIP_SPECS[norm_target]
        physical_kb = spec['physical_ram_kb']
        usable_kb = map_dram_usable_kb or spec['default_usable_ram_kb']
        if not ram_int_cap or ram_int_cap < 32:
            ram_int_cap = usable_kb
        ram_int_note = f"【IDF可用 {ram_int_cap}KB / 芯片物理 {physical_kb}KB】"
        if not flash_cap:
            flash_cap = 8192 if ('S3' in norm_target or 'P4' in norm_target) else 4096

    # 4. Other Microcontrollers
    if not ram_int_note:
        chip_db = [
            (r'STM32F103[C|R|V|T][8|B]', 128, 20),
            (r'STM32F103[R|V|Z][C|D|E]', 512, 64),
            (r'STM32F40[1|2]', 512, 96),
            (r'STM32F40[5|7]', 1024, 192),
            (r'STM32F42[7|9]', 2048, 256),
            (r'STM32H7[4|5]', 2048, 1024),
            (r'STM32G0', 128, 36),
            (r'STM32G4', 512, 128),
            (r'MSPM0G3507', 128, 32),
            (r'MSPM0L1306', 64, 4),
            (r'CH32V103', 64, 20),
            (r'CH32V203', 64, 20),
            (r'CH32V307', 256, 64),
            (r'CH32F103', 64, 20),
        ]
        for pat, c_fl, c_ram in chip_db:
            if re.search(pat, full_path_upper):
                if not flash_cap:
                    flash_cap = c_fl
                if not ram_int_cap:
                    ram_int_cap = c_ram
                ram_int_note = f"【片内 SRAM: {ram_int_cap or c_ram}KB】"
                break

    # 5. Fallback for completely unknown chips: only guess if NONE was detected
    standards_kb = [16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    def fallback_guess(used_b, default_val):
        used_kb = used_b / 1024.0
        for sz in standards_kb:
            if sz >= used_kb:
                return sz
        return max(default_val, int(used_kb * 1.25))

    if not flash_cap or flash_cap <= 0:
        flash_cap = fallback_guess(flash_used, 512)
    if not ram_int_cap or ram_int_cap <= 0:
        ram_int_cap = fallback_guess(ram_int_used, 128)
    if has_ext_ram and (not ram_ext_cap or ram_ext_cap <= 0):
        ram_ext_cap = fallback_guess(ram_ext_used, 8192)
    elif not has_ext_ram:
        ram_ext_cap = 0

    return flash_cap, ram_int_cap, ram_ext_cap, has_ext_ram, ext_ram_name, ram_int_note


class FirmwareParser:
    """Universal parser for firmware binaries and map files."""

    @staticmethod
    def parse_file(file_path: str) -> Dict[str, Any]:
        """Auto-detect format and parse."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.elf', '.axf', '.out', '.o']:
            res = FirmwareParser.parse_elf(file_path)
        elif ext == '.map':
            res = FirmwareParser.parse_map(file_path)
        else:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            if magic == b'\x7fELF':
                res = FirmwareParser.parse_elf(file_path)
            else:
                res = FirmwareParser.parse_map(file_path)

        # Smart chip capacity detection
        fl_cap, ram_int_cap, ram_ext_cap, has_ext, ext_name, int_note = detect_chip_limits(
            file_path,
            res.get('flash_total', 0),
            res.get('ram_internal_total', 0),
            res.get('ram_external_total', 0),
            res.get('esp_target'),
            res.get('map_capacities')
        )

        # Use explicitly detected capacity if parser didn't hard-assign one
        if not res.get('chip_flash_kb'):
            res['chip_flash_kb'] = fl_cap
        if not res.get('chip_internal_ram_kb'):
            res['chip_internal_ram_kb'] = ram_int_cap
        if not res.get('chip_external_ram_kb'):
            res['chip_external_ram_kb'] = ram_ext_cap
        if 'has_external_ram' not in res or not res['has_external_ram']:
            res['has_external_ram'] = has_ext
        if not res.get('external_ram_name'):
            res['external_ram_name'] = ext_name
        if not res.get('ram_int_note'):
            res['ram_int_note'] = int_note

        return res

    @staticmethod
    def parse_elf(file_path: str) -> Dict[str, Any]:
        if not HAS_ELFTOOLS:
            raise RuntimeError("缺少 pyelftools 依赖，请运行: pip install pyelftools")

        result = {
            'file_name': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_type': 'ELF / AXF 固件目标文件',
            'arch': 'Unknown',
            'entry': 0,
            'flash_total': 0,
            'ram_internal_total': 0,
            'ram_external_total': 0,
            'ram_total': 0,
            'sections': [],
            'symbols': [],
            'modules': {},
            'raw_info': [],
            'parsed_ok': True
        }

        with open(file_path, 'rb') as f:
            elf = ELFFile(f)

            machine = elf.header['e_machine']
            result['arch'] = str(machine).replace('EM_', '')
            result['entry'] = elf.header['e_entry']
            bits = elf.elfclass
            endian = 'Little Endian' if elf.little_endian else 'Big Endian'
            result['raw_info'].append(f"ELF 类型: {elf.header['e_type']}, {bits} 位, {endian}")
            result['raw_info'].append(f"目标架构: {result['arch']}, 入口地址: 0x{result['entry']:08X}")

            sec_idx_to_name = {}
            flash_bytes = 0
            ram_int_bytes = 0
            ram_ext_bytes = 0

            for i, sec in enumerate(elf.iter_sections()):
                sec_name = sec.name
                sec_idx_to_name[i] = sec_name
                sh_size = sec['sh_size']
                sh_addr = sec['sh_addr']
                sh_offset = sec['sh_offset']
                sh_flags = sec['sh_flags']
                sh_type = sec['sh_type']

                if sh_size == 0 and not sec_name:
                    continue

                is_alloc = bool(sh_flags & 0x2)   # SHF_ALLOC
                is_write = bool(sh_flags & 0x1)   # SHF_WRITE
                is_exec = bool(sh_flags & 0x4)    # SHF_EXECINSTR
                is_nobits = (sh_type == 'SHT_NOBITS')
                has_file_content = not is_nobits

                # Find Load Memory Address (LMA) from Program Headers
                sec_lma = sh_addr
                for seg in elf.iter_segments():
                    if seg['p_type'] == 'PT_LOAD':
                        if has_file_content and seg['p_offset'] <= sh_offset < (seg['p_offset'] + seg['p_filesz']):
                            sec_lma = seg['p_paddr'] + (sh_offset - seg['p_offset'])
                            break
                        elif seg['p_vaddr'] <= sh_addr < (seg['p_vaddr'] + seg['p_memsz']):
                            sec_lma = seg['p_paddr'] + (sh_addr - seg['p_vaddr'])
                            break

                category = "Other"
                sec_lower = sec_name.lower()

                # Filter ESP-IDF dummy alignment sections (only dummy sections)
                if sec_lower.endswith('.dummy') or sec_lower.endswith('_dummy'):
                    category = "保留 / 内存对齐占位 (Dummy/Reserved)"
                elif is_alloc:
                    is_ext = is_external_ram_section(sec_name, sh_addr)
                    is_int = is_internal_ram_address(sh_addr, sec_name)
                    has_separate_lma = (sec_lma != sh_addr and has_file_content)

                    # Account Flash:
                    # Stored in Flash if it has file content (PROGBITS)
                    # Exclude sections that are purely host debug/metadata
                    is_flash_stored = has_file_content and not is_debug_or_metadata(sec_name, sh_addr)

                    if is_flash_stored:
                        flash_bytes += sh_size

                    # Account RAM:
                    if is_ext:
                        ram_ext_bytes += sh_size
                        if is_flash_stored:
                            category = "片外 RAM & Flash (Data/Code)"
                        else:
                            category = "片外 RAM (BSS/NOLOAD)"
                    elif is_int:
                        # In ESP32, flash.rodata and flash.text are XIP from Flash
                        if 'flash.rodata' in sec_lower or 'flash.text' in sec_lower or 'flash.appdesc' in sec_lower or 'flash.init_array' in sec_lower:
                            if 'rodata' in sec_lower or 'appdesc' in sec_lower:
                                category = "Flash (RO-Data)"
                            else:
                                category = "Flash (Code)"
                        else:
                            ram_int_bytes += sh_size
                            if is_flash_stored:
                                category = "片内 RAM & Flash (Data/Code)"
                            else:
                                category = "片内 RAM (Internal SRAM)"
                    else:
                        # Resides in Flash
                        if is_exec:
                            category = "Flash (Code)"
                        else:
                            category = "Flash (RO-Data)"

                elif sec_name.startswith('.debug'):
                    category = "Debug Info"
                elif sec_name.startswith('.comment') or sec_name.startswith('.ARM.attributes') or sec_name.startswith('.riscv.attributes'):
                    category = "Metadata"

                result['sections'].append({
                    'index': i,
                    'name': sec_name or f"<sec_{i}>",
                    'type': sh_type,
                    'address': sh_addr,
                    'address_hex': f"0x{sh_addr:08X}" if is_alloc else "-",
                    'size': sh_size,
                    'size_str': format_bytes(sh_size),
                    'category': category,
                    'flags': f"{'A' if is_alloc else ''}{'W' if is_write else ''}{'X' if is_exec else ''}"
                })

            result['flash_total'] = flash_bytes
            result['ram_internal_total'] = ram_int_bytes
            result['ram_external_total'] = ram_ext_bytes
            result['ram_total'] = ram_int_bytes + ram_ext_bytes

            # Symbols
            symtab = elf.get_section_by_name('.symtab')
            if symtab and isinstance(symtab, SymbolTableSection):
                for sym in symtab.iter_symbols():
                    name = sym.name
                    if name.startswith('IDF_TARGET_'):
                        result['esp_target'] = name.replace('IDF_TARGET_', '').upper()
                    size = sym['st_size']
                    val = sym['st_value']
                    st_type = sym['st_info']['type']
                    st_bind = sym['st_info']['bind']
                    shndx = sym['st_shndx']

                    if not name or size == 0:
                        continue

                    sec_name = sec_idx_to_name.get(shndx, f"SEC_{shndx}") if isinstance(shndx, int) else str(shndx)

                    type_str = "Other"
                    if st_type == 'STT_FUNC':
                        type_str = "函数 (FUNC)"
                    elif st_type == 'STT_OBJECT':
                        type_str = "全局/静态变量 (OBJECT)"

                    result['symbols'].append({
                        'name': name,
                        'size': size,
                        'size_str': format_bytes(size),
                        'address': val,
                        'address_hex': f"0x{val:08X}",
                        'type': type_str,
                        'bind': st_bind,
                        'section': sec_name
                    })

            result['symbols'].sort(key=lambda x: x['size'], reverse=True)

        return result

    @staticmethod
    def parse_map(file_path: str) -> Dict[str, Any]:
        """Parse Linker Map file (Keil MDK, GCC, or TI)."""
        result = {
            'file_name': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_type': 'Linker Map 链接器映射文件',
            'arch': 'Unknown',
            'entry': 0,
            'flash_total': 0,
            'ram_internal_total': 0,
            'ram_external_total': 0,
            'ram_total': 0,
            'sections': [],
            'symbols': [],
            'modules': {},
            'raw_info': [],
            'parsed_ok': True,
            'warning_message': ''
        }

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        if "Image component sizes" in content or "Component size" in content:
            result['file_type'] = 'Keil MDK (ARMCC/AC6) Map 文件'
            FirmwareParser._parse_keil_map(content, result)
        elif "TI ARM Clang Linker" in content or "TI ARM Linker" in content or ("MEMORY CONFIGURATION" in content and "SEGMENT ALLOCATION MAP" in content):
            result['file_type'] = 'TI (MSPM0 / CCS) Linker Map 文件'
            FirmwareParser._parse_ti_map(content, result)
        elif "Linker script and memory map" in content or "Memory Configuration" in content:
            result['file_type'] = 'GNU GCC / ESP-IDF Linker Map 文件'
            m_t = re.search(r'IDF_TARGET_([a-zA-Z0-9]+)\s*=', content)
            if m_t:
                result['esp_target'] = m_t.group(1).upper()
            FirmwareParser._parse_gcc_map(content, result)
        else:
            result['file_type'] = '未知格式 Map 文件'
            result['parsed_ok'] = False
            result['warning_message'] = "无法识别此 Map 文件格式（未匹配 Keil / GCC / TI 链接器语法）。建议直接拖入编译生成的 .elf / .axf / .out 目标文件！"
            FirmwareParser._parse_generic_map(content, result)

        return result

    @staticmethod
    def _parse_keil_map(content: str, result: Dict[str, Any]):
        """Parse Keil ARM Linker Map components."""
        comp_pattern = re.compile(
            r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$',
            re.MULTILINE
        )
        rom_match = re.search(r'Total ROM Size\s*\([^)]*\)\s*(\d+)', content)
        rw_match = re.search(r'Total RW\s*Size\s*\([^)]*\)\s*(\d+)', content)

        code_sum, ro_sum, rw_sum, zi_sum = 0, 0, 0, 0

        for match in comp_pattern.finditer(content):
            code = int(match.group(1))
            ro = int(match.group(3))
            rw = int(match.group(4))
            zi = int(match.group(5))
            obj_name = match.group(7).strip()

            if "Grand Totals" in obj_name or "Total" in obj_name:
                continue

            code_sum += code
            ro_sum += ro
            rw_sum += rw
            zi_sum += zi

            result['modules'][obj_name] = {
                'name': obj_name,
                'code': code,
                'ro_data': ro,
                'rw_data': rw,
                'zi_data': zi,
                'flash': code + ro + rw,
                'ram': rw + zi
            }

        result['flash_total'] = int(rom_match.group(1)) if rom_match else (code_sum + ro_sum + rw_sum)
        ram_total = int(rw_match.group(1)) if rw_match else (rw_sum + zi_sum)
        result['ram_internal_total'] = ram_total
        result['ram_external_total'] = 0
        result['ram_total'] = ram_total

        result['sections'] = [
            {'index': 1, 'name': 'Code (代码指令)', 'type': 'SHT_PROGBITS', 'address': 0, 'address_hex': '-', 'size': code_sum, 'size_str': format_bytes(code_sum), 'category': 'Flash (Code)', 'flags': 'AX'},
            {'index': 2, 'name': 'RO Data (只读数据)', 'type': 'SHT_PROGBITS', 'address': 0, 'address_hex': '-', 'size': ro_sum, 'size_str': format_bytes(ro_sum), 'category': 'Flash (RO-Data)', 'flags': 'A'},
            {'index': 3, 'name': 'RW Data (已初始化数据)', 'type': 'SHT_PROGBITS', 'address': 0, 'address_hex': '-', 'size': rw_sum, 'size_str': format_bytes(rw_sum), 'category': '片内 RAM & Flash (Data)', 'flags': 'AW'},
            {'index': 4, 'name': 'ZI Data (未初始化数据)', 'type': 'SHT_NOBITS', 'address': 0, 'address_hex': '-', 'size': zi_sum, 'size_str': format_bytes(zi_sum), 'category': '片内 RAM (Internal SRAM)', 'flags': 'AW'}
        ]

        sym_pattern = re.compile(
            r'^\s*([a-zA-Z0-9_$]+)\s+(0x[0-9a-fA-F]+)\s+(?:ARM|Thumb)?\s*(Code|Data)\s+(\d+)\s+(.+)$',
            re.MULTILINE
        )
        for sm in sym_pattern.finditer(content):
            s_name = sm.group(1)
            s_addr = int(sm.group(2), 16)
            s_kind = sm.group(3)
            s_size = int(sm.group(4))
            s_obj = sm.group(5).strip()
            if s_size > 0:
                result['symbols'].append({
                    'name': s_name,
                    'size': s_size,
                    'size_str': format_bytes(s_size),
                    'address': s_addr,
                    'address_hex': f"0x{s_addr:08X}",
                    'type': "函数 (FUNC)" if s_kind == "Code" else "全局/静态变量 (OBJECT)",
                    'bind': 'GLOBAL',
                    'section': s_obj
                })
        result['symbols'].sort(key=lambda x: x['size'], reverse=True)

    @staticmethod
    def _parse_ti_map(content: str, result: Dict[str, Any]):
        """Parse TI ARM Clang / TI CCS Linker Map."""
        flash_match = re.search(r'^\s*FLASH\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', content, re.MULTILINE)
        sram_match = re.search(r'^\s*SRAM\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', content, re.MULTILINE)

        if flash_match:
            result['flash_total'] = int(flash_match.group(3), 16)
            result['chip_flash_kb'] = int(flash_match.group(2), 16) // 1024
        if sram_match:
            ram_tot = int(sram_match.group(3), 16)
            result['ram_internal_total'] = ram_tot
            result['ram_external_total'] = 0
            result['ram_total'] = ram_tot
            result['chip_internal_ram_kb'] = int(sram_match.group(2), 16) // 1024

        seg_split = content.split('SEGMENT ALLOCATION MAP')
        if len(seg_split) > 1:
            seg_body = seg_split[1].split('SECTION ALLOCATION MAP')[0]
            sec_idx = 0
            for line in seg_body.splitlines():
                m = re.match(r'^\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([rwx-]+)\s+(\.[a-zA-Z0-9_.\-]+)', line)
                if m:
                    sec_idx += 1
                    vma = int(m.group(1), 16)
                    length = int(m.group(3), 16)
                    attrs = m.group(5)
                    name = m.group(6)

                    category = "Other"
                    if 'w' in attrs:
                        if name in ['.bss', '.stack', '.sysmem', 'COMMON']:
                            category = "片内 RAM (Internal SRAM)"
                        else:
                            category = "片内 RAM & Flash (Data)"
                    elif 'x' in attrs or name in ['.text', '.intvecs']:
                        category = "Flash (Code)"
                    elif 'r' in attrs:
                        category = "Flash (RO-Data)"

                    result['sections'].append({
                        'index': sec_idx,
                        'name': name,
                        'type': 'PROGBITS' if 'BSS' not in category else 'NOBITS',
                        'address': vma,
                        'address_hex': f"0x{vma:08X}",
                        'size': length,
                        'size_str': format_bytes(length),
                        'category': category,
                        'flags': attrs
                    })

        sec_split = content.split('SECTION ALLOCATION MAP')
        if len(sec_split) > 1:
            sec_body = sec_split[1].split('GLOBAL SYMBOLS')[0]
            pattern = re.compile(r'^\s{10,24}([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+(.+?)(?:\s+\((.*?)\))?$', re.MULTILINE)
            for addr_s, len_s, obj, sym in pattern.findall(sec_body):
                addr = int(addr_s, 16)
                length = int(len_s, 16)
                if length > 0:
                    clean_obj = obj.strip()
                    name = sym.split(':')[-1] if sym else clean_obj
                    name = re.sub(r'^\.(text|bss|data|rodata)\.', '', name)

                    is_func = addr < 0x20000000
                    result['symbols'].append({
                        'name': name,
                        'size': length,
                        'size_str': format_bytes(length),
                        'address': addr,
                        'address_hex': f"0x{addr:08X}",
                        'type': "函数 (FUNC)" if is_func else "全局/静态变量 (OBJECT)",
                        'bind': 'GLOBAL',
                        'section': clean_obj
                    })

            result['symbols'].sort(key=lambda x: x['size'], reverse=True)

    @staticmethod
    def _parse_gcc_map(content: str, result: Dict[str, Any]):
        """Parse GNU GCC / ESP-IDF Linker Map with multi-line unwrapping and load addresses."""
        # 1. Parse Memory Configuration if present
        map_caps = {}
        mem_cfg = re.search(r'Memory Configuration.*?\n\nName\s+Origin\s+Length\s+Attributes\n(.*?)\n\n', content, re.DOTALL)
        if mem_cfg:
            for line in mem_cfg.group(1).strip().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    r_name = parts[0].lower()
                    r_orig = int(parts[1], 16)
                    r_len = int(parts[2], 16) // 1024
                    r_attrs = parts[3].lower()
                    if 0 < r_len < 1024 * 1024:
                        if 'w' in r_attrs or 'sram' in r_name or 'dram' in r_name:
                            if any(k in r_name for k in ['ext', 'sdram', 'psram']) or r_orig >= 0x60000000:
                                map_caps['ram_ext'] = r_len
                            else:
                                map_caps['ram_int'] = r_len
                        elif 'x' in r_attrs or 'r' in r_attrs or 'flash' in r_name or 'rom' in r_name:
                            map_caps['flash'] = r_len

        result['map_capacities'] = map_caps

        # 2. Multi-line unwrapping state machine
        lines = content.splitlines()
        in_map = False
        unwrapped = []
        pending_name = None

        for line in lines:
            if "Linker script and memory map" in line:
                in_map = True
                continue
            if not in_map:
                continue

            # Check if line is a wrapped section name alone: e.g. " .text.long_name" or ".long_section"
            m_name_only = re.match(r'^(\s{0,2}\.[a-zA-Z0-9_.\-]+)\s*$', line)
            if m_name_only:
                pending_name = m_name_only.group(1)
                continue

            if pending_name:
                m_addr = re.match(r'^\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)(.*)$', line)
                if m_addr:
                    unwrapped.append(f'{pending_name} {m_addr.group(1)} {m_addr.group(2)}{m_addr.group(3)}')
                    pending_name = None
                    continue
                else:
                    unwrapped.append(pending_name)
                    pending_name = None

            unwrapped.append(line)

        # 3. Parse unwrapped output sections and symbols
        out_sec_regex = re.compile(r'^(\.[a-zA-Z0-9_.\-]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)(?:\s+load address\s+(0x[0-9a-fA-F]+))?')
        sub_sec_regex = re.compile(r'^\s+(\.[a-zA-Z0-9_.\-]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+)$')

        flash_bytes = 0
        ram_int_bytes = 0
        ram_ext_bytes = 0
        sec_idx = 0
        current_sec = None

        for line in unwrapped:
            m = out_sec_regex.match(line)
            if m:
                sec_name = m.group(1)
                addr = int(m.group(2), 16)
                size = int(m.group(3), 16)
                has_load = bool(m.group(4))

                if size == 0 or sec_name.endswith('.dummy') or sec_name.endswith('_dummy'):
                    continue
                if is_debug_or_metadata(sec_name, addr):
                    continue

                sec_idx += 1
                s_lower = sec_name.lower()
                is_ext = is_external_ram_section(sec_name, addr)
                is_int = is_internal_ram_address(addr, sec_name)

                cat = "Other"
                if has_load:
                    # Stored in Flash, loaded into RAM at boot
                    flash_bytes += size
                    if is_ext:
                        cat = "片外 RAM & Flash (Data/Code)"
                        ram_ext_bytes += size
                    else:
                        cat = "片内 RAM & Flash (Data/Code)"
                        ram_int_bytes += size
                elif is_ext:
                    cat = "片外 RAM (PSRAM/SDRAM)"
                    ram_ext_bytes += size
                elif is_int:
                    # In ESP-IDF:
                    if 'flash.rodata' in s_lower or 'flash.text' in s_lower or 'flash.appdesc' in s_lower or 'flash.init_array' in s_lower:
                        flash_bytes += size
                        cat = "Flash (RO-Data)" if 'rodata' in s_lower or 'appdesc' in s_lower else "Flash (Code)"
                    elif 'iram' in s_lower or 'data' in s_lower or 'rtc' in s_lower or 'tcm.text' in s_lower or 'tcm.data' in s_lower:
                        # Stored in Flash, loaded into internal RAM at boot
                        flash_bytes += size
                        ram_int_bytes += size
                        cat = "片内 RAM & Flash (Data/Code)"
                    else:
                        cat = "片内 RAM (Internal SRAM)"
                        ram_int_bytes += size
                else:
                    # Flash section (code, rodata, assets, etc.)
                    flash_bytes += size
                    if 'rodata' in s_lower or 'assets' in s_lower or 'appdesc' in s_lower or 'exidx' in s_lower:
                        cat = "Flash (RO-Data)"
                    else:
                        cat = "Flash (Code)"

                result['sections'].append({
                    'index': sec_idx,
                    'name': sec_name,
                    'type': 'PROGBITS' if 'BSS' not in cat else 'NOBITS',
                    'address': addr,
                    'address_hex': f"0x{addr:08X}",
                    'size': size,
                    'size_str': format_bytes(size),
                    'category': cat,
                    'flags': 'ALLOC'
                })
                current_sec = sec_name
                continue

            sub_m = sub_sec_regex.match(line)
            if sub_m:
                sub_name = sub_m.group(1)
                s_addr = int(sub_m.group(2), 16)
                s_size = int(sub_m.group(3), 16)
                s_obj = sub_m.group(4).strip()
                if s_size > 0:
                    clean_name = sub_name.split('.')[-1] if '.' in sub_name[1:] else sub_name
                    result['symbols'].append({
                        'name': clean_name,
                        'size': s_size,
                        'size_str': format_bytes(s_size),
                        'address': s_addr,
                        'address_hex': f"0x{s_addr:08X}",
                        'type': "代码/数据",
                        'bind': 'LOCAL',
                        'section': f"{current_sec or ''} ({os.path.basename(s_obj)})"
                    })

        result['flash_total'] = flash_bytes
        result['ram_internal_total'] = ram_int_bytes
        result['ram_external_total'] = ram_ext_bytes
        result['ram_total'] = ram_int_bytes + ram_ext_bytes
        result['symbols'].sort(key=lambda x: x['size'], reverse=True)

    @staticmethod
    def _parse_generic_map(content: str, result: Dict[str, Any]):
        """Fallback for generic map files."""
        lines = content.splitlines()[:50]
        result['raw_info'].extend(lines)
