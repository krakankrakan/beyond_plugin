from binaryninja import *
from binaryninja import Architecture
from binaryninja import BinaryView, BinaryViewType
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType, Endianness
from binaryninja.types import Type, Symbol

import beyond.calling_convention as calling_convention

SHADOW_RAM_START = 0xF000000
RAM_START = 0x4000000
PERIPHERALS_START = 0x2000000
EEPROM_REGS_START = 0x1000000
FLASH_MAP_START = 0x80000
ENTRYPOINT_ADDR = FLASH_MAP_START + 0x38

class JN51xxFlashView(BinaryView):
    name = "Beyond 2 Image Loader"
    long_name = "Beyond 2 Image Loader"
    entry = 0

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture["beyond2"].standalone_platform

        # Parse all segments

        # 32 bit
        data_section_flash_start = 0

        # 16 bit
        data_section_load_start = 0
        data_section_length = 0
        bss_section_start = 0
        bss_section_length = 0

        data_section_flash_start = int.from_bytes(data[0x24:0x28], "big")
        data_section_load_start  = int.from_bytes(data[0x28:0x2A], "big")
        data_section_length      = int.from_bytes(data[0x2A:0x2C], "big")
        bss_section_start        = int.from_bytes(data[0x2C:0x2E], "big")
        bss_section_length       = int.from_bytes(data[0x2E:0x30], "big")

        # Add the segments and sections
        self.add_auto_segment(FLASH_MAP_START + 0x38 + 4, len(data) - 0x38 - 4, 0x38 + 4, len(data) - 0x38 - 4, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode)
        
        #print(hex(data_section_flash_start))
        #print(hex(data_section_length * 4))
        #self.add_auto_segment(EEPROM_REGS_START, FLASH_MAP_START, data_section_flash_start - FLASH_MAP_START, data_section_length * 4, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        
        self.add_auto_segment(EEPROM_REGS_START, 0x1000000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        self.add_auto_segment(PERIPHERALS_START, 0x3000000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_segment(RAM_START, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_segment(SHADOW_RAM_START, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        self.add_user_section('Application Code', FLASH_MAP_START + 0x38 + 4, 0xC0000 - 0x38 - 4, SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_user_section('Flash/EEPROM', EEPROM_REGS_START, 0x1000000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_user_section('Peripherals', PERIPHERALS_START, 0x3000000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_user_section('RAM', RAM_START, 0x8000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_user_section('Shadow RAM', SHADOW_RAM_START, 0x8000, SectionSemantics.ReadWriteDataSectionSemantics)

        #self.add_user_section('ROM Text', FLASH_MAP_START, len(data), SectionSemantics.ReadOnlyCodeSectionSemantics)
        #self.add_user_section('ROM Data', data_section_load_start, data_section_length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        #self.add_user_section('ROM BSS', bss_section_start, bss_section_length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        # Parse and mark entrypoints
        wakeup_entry = int.from_bytes(data[0x30:0x34], "big")
        reset_entry  = int.from_bytes(data[0x34:0x38], "big")
        self.entry = reset_entry

        try:
            self.add_function(wakeup_entry)
            self.get_function_at(wakeup_entry).name = 'wakeup_entry'
            self.add_function(reset_entry)
            self.get_function_at(reset_entry).name  = 'reset_entry'

            #self.add_entry_point(ENTRYPOINT_ADDR)
            #self.get_function_at(ENTRYPOINT_ADDR).name = 'entry'

            # Create a custom structure type for the header
            header_struct_type = Structure()
            header_struct_type.insert(FLASH_MAP_START + 0x0, Type.array(Type.int(1, sign=False), 12), name="boot_image_record")
            header_struct_type.insert(FLASH_MAP_START + 0xC, Type.int(1, sign=False), name="configuration")
            header_struct_type.insert(FLASH_MAP_START + 0xD, Type.int(1, sign=False), name="status")
            header_struct_type.insert(FLASH_MAP_START + 0xE, Type.int(2, sign=False), name="application_id")
            header_struct_type.insert(FLASH_MAP_START + 0x10, Type.int(4, sign=False), name="encryption_init_vector")
            header_struct_type.insert(FLASH_MAP_START + 0x1E, Type.int(2, sign=False), name="configuration_options")
            header_struct_type.insert(FLASH_MAP_START + 0x20, Type.int(4, sign=False), name="binary_len")
            header_struct_type.insert(FLASH_MAP_START + 0x24, Type.int(4, sign=False), name="data_flash_start")
            header_struct_type.insert(FLASH_MAP_START + 0x28, Type.int(2, sign=False), name="data_section_load_addr")
            header_struct_type.insert(FLASH_MAP_START + 0x2A, Type.int(2, sign=False), name="data_section_load_len")
            header_struct_type.insert(FLASH_MAP_START + 0x2C, Type.int(2, sign=False), name="bss_section_load_addr")
            header_struct_type.insert(FLASH_MAP_START + 0x2E, Type.int(2, sign=False), name="data_section_load_len")
            header_struct_type.insert(FLASH_MAP_START + 0x30, Type.int(4, sign=False), name="wakeup_entry")
            header_struct_type.insert(FLASH_MAP_START + 0x34, Type.int(4, sign=False), name="reset_entry")

            t = Type.structure_type(header_struct_type)

            self.define_user_data_var(0x0, t)
            self.define_user_symbol(Symbol(SymbolType.DataSymbol, 0x0, "flash_hdr", "flash_header"))
        except:
            pass

    @classmethod
    def is_valid_for_data(cls, data):
        magic = b"\x12\x34\x56\x78\x11\x22\x33\x44\x55\x66\x77\x88"

        if len(data) < len(magic) + 4:
            return False

        if data[:len(magic)] == magic:
            return True

        return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry

def register_view():
    JN51xxFlashView.register()

    a = binaryninja.architecture.Architecture["beyond2"]

    BinaryViewType['ELF'].register_arch(0x8472, Endianness.BigEndian, a)

    # Set calling convention
    a.register_calling_convention(calling_convention.BeyondCallingConvention(a, "default"))
    a.standalone_platform.default_calling_convention = a.calling_conventions["default"]