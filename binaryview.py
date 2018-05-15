import struct
import traceback

from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol, Type
from binaryninja.log import log_error
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

class Native(BinaryView):
    name = 'MCS48'

    CODE_OFFSET = 0x8000

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def init(self):
        self.platform = Platform['8049_rb0mb0']

        length = len(self.parent_view)

        try:
            # create the data memory segment and section
            self.add_auto_segment(0, 128, 0, 0, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
            self.add_auto_section('.ram', 0, 128, SectionSemantics.ReadWriteDataSectionSemantics)

            # create the program memory segment, section and entry point
            self.add_auto_segment(self.CODE_OFFSET, length, 0, length, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_auto_section('.rom', self.CODE_OFFSET, length, SectionSemantics.ReadOnlyCodeSectionSemantics)
            self.add_entry_point(self.CODE_OFFSET)

            self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.FunctionSymbol, self.CODE_OFFSET | 0, 'reset'), None, self.platform)
            self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.FunctionSymbol, self.CODE_OFFSET | 3, 'interrupt'), None, self.platform)
            self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.FunctionSymbol, self.CODE_OFFSET | 7, 'timer'), None, self.platform)

            # working registers
            for n in range(8):
                self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.DataSymbol, n, 'R{}'.format(n)), Type.int(1, False), self.platform)
                self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.DataSymbol, n + 24, 'R{}\''.format(n)), Type.int(1, False), self.platform)

            # stack registers
            for n in range(8):
                self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.DataSymbol, n * 2 + 8, 'S{}'.format(n)), Type.int(2, False), self.platform)

            return True

        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return True

    def perform_get_entry_point(self):
        return self.CODE_OFFSET | 0
