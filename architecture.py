import re

import binaryninja._binaryninjacore as core

from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, ILRegister, LLIL_TEMP
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.log import log_error
from binaryninja.enums import (BranchType, Endianness, InstructionTextTokenType, LowLevelILOperation, LowLevelILFlagCondition, FlagRole)

# enable register and memory banks
REG_BANKS = False
MEM_BANKS = False

# treat working registers as actual registers
WREG_REG = True

CODE_OFFSET = 0x8000

def CODE_ADDR(page, offset):
    return CODE_OFFSET | (page & 0xf00) | offset

# TODO: call/retr restore PSW flags
# TODO: 8021/8022: call stores unincremented pc, which is incremented by ret but not by reti
def call_helper(il, addr):
    # get sp and compute address
    il.append(il.set_reg(1, LLIL_TEMP(0), il.and_expr(1, il.reg(1, 'PSW'), il.const(1, 0x7))))
    il.append(il.set_reg(2, LLIL_TEMP(1), il.add(2, il.shift_left(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 1)), il.const(2, 8))))

    # store return address and psw
    il.append(il.store(2, il.reg(2, LLIL_TEMP(1)),
        il.or_expr(2, il.shift_left(
            2, 
            il.and_expr(1, il.reg(1, 'PSW'), il.const(1, 0xf0)), il.const(1, 8)), 
            il.const(2, (il.current_address & 0xfff) + 2)
        )
    ))

    # increment sp
    il.append(il.set_reg(1, 'PSW', il.or_expr(
        1, 
        il.and_expr(1, il.reg(1, 'PSW'), il.const(1, 0xf8)), 
        il.and_expr(
            1, 
            il.add(
                1, 
                il.reg(1, LLIL_TEMP(0)), 
                il.const(1, 1)), 
            il.const(1, 0x7)
        )
    )))

    # generate call
    if MEM_BANKS:
        # TODO: get address bit 11 from DBF
        pass
    else:
        il.append(il.call(il.const_pointer(2, addr)))

def ret_helper(il, psw):
    # get and decrement sp
    il.append(il.set_reg(1, LLIL_TEMP(0), il.and_expr(1, il.reg(1, 'PSW'), il.const(1, 0x7))))
    il.append(il.set_reg(1, LLIL_TEMP(0), il.and_expr(1, il.sub(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 1)), il.const(1, 0x7))))

    # load return address and psw
    il.append(il.set_reg(2, LLIL_TEMP(1), il.load(2, il.add(2, il.shift_left(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 1)), il.const(2, 8)))))

    # update psw
    if psw:
        il.append(il.set_reg(1, 'PSW', il.or_expr(
            1, 
            il.and_expr(1, il.reg(1, 'PSW'), il.const(1, 0xf)), 
            il.logical_shift_right(
                1, 
                il.reg(2, LLIL_TEMP(1)), 
                il.const(1, 12)
            )
        )))
    else:
        il.append(il.set_reg(
            1, 
            'PSW', 
            il.or_expr(
                1, 
                il.and_expr(1, il.reg(1, 'PSW'), il.const(1, 0xf8)), 
                il.reg(1, LLIL_TEMP(0))
            )
        ))

    # generate return
    il.append(il.ret(
        il.or_expr(
            2,
            il.and_expr(2, il.reg(2, LLIL_TEMP(1)), il.const(2, 0xfff)),
            il.const(2, CODE_OFFSET)
        )
    ))

def branch(il, addr):
    if MEM_BANKS:
        # TODO: get address bit 11 from DBF
        pass
    else:
        # try to find a label for the branch target
        taken = il.get_label_for_address(il.arch, addr)

        # handle unconditional branch
        if taken is not None:
            il.append(il.goto(taken))
        else:
            il.append(il.jump(il.const_pointer(2, addr)))

def cond_branch(il, addr, cond, arg=None):
    # try to find a label for the branch target
    taken = il.get_label_for_address(il.arch, addr)

    # build the conditional expression
    if cond == 'Z':
        expr = il.compare_equal(1, il.reg(1, 'A'), il.const(1, 0))
    elif cond == 'NZ':
        expr = il.compare_not_equal(1, il.reg(1, 'A'), il.const(1, 0))
    elif cond == 'B':
        expr = il.and_expr(1, il.reg(1, 'A'), il.const(1, 1 << arg))
    else:
        expr = il.compare_equal(1, il.flag(cond), il.const(0, arg))

    # create taken target
    taken_found = True
    if taken is None:
        taken = LowLevelILLabel()
        taken_found = False

    # create untaken target
    untaken_found = True
    untaken = il.get_label_for_address(il.arch, il.current_address + 2)
    if untaken is None:
        untaken = LowLevelILLabel()
        untaken_found = False

    # generate the conditional branch LLIL
    il.append(il.if_expr(expr, taken, untaken))

    # generate a jump to the branch target if a label couldn't be found
    if not taken_found:
        il.mark_label(taken)
        il.append(il.jump(il.const_pointer(2, addr)))

    # generate a label for the untaken branch
    if not untaken_found:
        il.mark_label(untaken)

class MCS48_Base(Architecture):

    address_size = 2
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 2

    regs = {
        'A': RegisterInfo('A', 1),
        'T': RegisterInfo('T', 1),
        'PSW': RegisterInfo('PSW', 1),
        'SP': RegisterInfo('SP', 1),
    }
    if WREG_REG:
        for reg in range(8):
            regs['R{}'.format(reg)] = RegisterInfo('R{}'.format(reg), 1)
        for reg in range(8):
            regs['R{}\''.format(reg)] = RegisterInfo('R{}\''.format(reg), 1)

    stack_pointer = 'SP'
    global_regs = ['T', 'PSW']

    # PSW: CY, AC, F0, BS, 1, S2, S1, S0
    # carry, aux carry, flag 0, bank select, stack pointer
    # BS:0, addr=0, BS:1, addr=24

    flags = [
        'CY', # carry
        'AC', # auxiliary carry
        'F0', # flag 0
        'BS', # bank switch

        'DBF',
        'F1', # flag 1

        'T0', # test 0
        'T1', # test 1
        'TF', # timer flag
        'INT' # interrupt
    ]

    # The first flag write type is ignored currently.
    # See: https://github.com/Vector35/binaryninja-api/issues/513
    flag_write_types = ['', 'C']
    flags_written_by_flag_write_type = {
        'C': ['CY'],
    }
    flag_roles = {
        'CY': FlagRole.CarryFlagRole,
        'AC': FlagRole.HalfCarryFlagRole,
        'F0': FlagRole.SpecialFlagRole,
        'BS': FlagRole.SpecialFlagRole,

        'DBF': FlagRole.SpecialFlagRole,
        'F1': FlagRole.SpecialFlagRole,

        'T0': FlagRole.SpecialFlagRole,
        'T1': FlagRole.SpecialFlagRole,
        'TF': FlagRole.SpecialFlagRole,
        'INT': FlagRole.SpecialFlagRole,
    }
    #flags_required_for_flag_condition = {}

    instructions = [
        # 0x00-0x0f
        [('NOP', 1), [],                lambda self, il: il.nop()],
        None,
        [('OUTL', 1), ['BUS', 'A'],     lambda self, il: il.reg(1, 'A')], # dummy read
        [('ADD', 2), ['A', '#IMM8'],    lambda self, il, imm: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), il.const(1, imm), 'C'))],
        [('JMP', 2), ['ADDR11'],        lambda self, il, imm: branch(il, CODE_ADDR(0x000, imm))],
        [('EN', 1), ['I']],
        None,
        [('DEC', 1), ['A'],             lambda self, il: il.set_reg(1, 'A', il.sub(1, il.reg(1, 'A'), il.const(1, 1)))],
        [('INS', 1), ['A', 'BUS'],      lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        [('IN', 1), ['A', 'P1'],        lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        [('IN', 1), ['A', 'P2'],        lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        None,
        [('MOVD', 1), ['A', 'P4'],      lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        [('MOVD', 1), ['A', 'P5'],      lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        [('MOVD', 1), ['A', 'P6'],      lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        [('MOVD', 1), ['A', 'P7'],      lambda self, il: il.set_reg(1, 'A', il.unimplemented())],
        # 0x10-0x1f
        [('INC', 1), ['@R0'],           lambda self, il: il.store(1, self.wreg_get(il, 0), il.add(1, il.load(1, self.wreg_get(il, 0)), il.const(1, 1)))],
        [('INC', 1), ['@R1'],           lambda self, il: il.store(1, self.wreg_get(il, 1), il.add(1, il.load(1, self.wreg_get(il, 1)), il.const(1, 1)))],
        [('JB0', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 0)],
        [('ADDC', 2), ['A', '#IMM8'],   lambda self, il, imm: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), il.const(1, imm), il.flag('CY'), 'C'))],
        [('CALL', 2), ['ADDR11'],       lambda self, il, imm: call_helper(il, CODE_ADDR(0x000, imm))],
        [('DIS', 1), ['I']],
        [('JTF', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'TF', 1)],
        [('INC', 1), ['A'],             lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), il.const(1, 1)))],
        [('INC', 1), ['R0'],            lambda self, il: self.wreg_set(il, 0, il.add(1, self.wreg_get(il, 0), il.const(1, 1)))],
        [('INC', 1), ['R1'],            lambda self, il: self.wreg_set(il, 1, il.add(1, self.wreg_get(il, 1), il.const(1, 1)))],
        [('INC', 1), ['R2'],            lambda self, il: self.wreg_set(il, 2, il.add(1, self.wreg_get(il, 2), il.const(1, 1)))],
        [('INC', 1), ['R3'],            lambda self, il: self.wreg_set(il, 3, il.add(1, self.wreg_get(il, 3), il.const(1, 1)))],
        [('INC', 1), ['R4'],            lambda self, il: self.wreg_set(il, 4, il.add(1, self.wreg_get(il, 4), il.const(1, 1)))],
        [('INC', 1), ['R5'],            lambda self, il: self.wreg_set(il, 5, il.add(1, self.wreg_get(il, 5), il.const(1, 1)))],
        [('INC', 1), ['R6'],            lambda self, il: self.wreg_set(il, 6, il.add(1, self.wreg_get(il, 6), il.const(1, 1)))],
        [('INC', 1), ['R7'],            lambda self, il: self.wreg_set(il, 7, il.add(1, self.wreg_get(il, 7), il.const(1, 1)))],
        # 0x20-0x2f
        [('XCH', 1), ['A', '@R0'],      lambda self, il: [
            il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), 
            il.set_reg(1, 'A', il.load(1, self.wreg_get(il, 0))), 
            self.wreg_set(il, 0, il.reg(1, LLIL_TEMP(1)))
        ]],
        [('XCH', 1), ['A', '@R1'],      lambda self, il: [
            il.set_reg(1, LLIL_TEMP(1), 
            il.reg(1, 'A')), il.set_reg(1, 'A', il.load(1, self.wreg_get(il, 1))), 
            self.wreg_set(il, 1, il.reg(1, LLIL_TEMP(1)))
        ]],
        None,
        [('MOV', 2), ['A', '#IMM8'],    lambda self, il, imm: il.set_reg(1, 'A', il.const(1, imm))],
        [('JMP', 2), ['ADDR11'],        lambda self, il, imm: branch(il, CODE_ADDR(0x100, imm))],
        [('EN', 1), ['TCNTI']],
        [('JNT0', 2), ['ADDR8'],        lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'T0', 0)],
        [('CLR', 1), ['A'],             lambda self, il: il.set_reg(1, 'A', il.const(1, 0))],
        [('XCH', 1), ['A', 'R0'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 0)), self.wreg_set(il, 0, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R1'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 1)), self.wreg_set(il, 1, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R2'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 2)), self.wreg_set(il, 2, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R3'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 3)), self.wreg_set(il, 3, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R4'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 4)), self.wreg_set(il, 4, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R5'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 5)), self.wreg_set(il, 5, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R6'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 6)), self.wreg_set(il, 6, il.reg(1, LLIL_TEMP(1)))]],
        [('XCH', 1), ['A', 'R7'],       lambda self, il: [il.set_reg(1, LLIL_TEMP(1), il.reg(1, 'A')), il.set_reg(1, 'A', self.wreg_get(il, 7)), self.wreg_set(il, 7, il.reg(1, LLIL_TEMP(1)))]],
        # 0x30-0x3f
        [('XCHD', 1), ['A', '@R0']],
        [('XCHD', 1), ['A', '@R1']],
        [('JB1', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 1)],
        None,
        [('CALL', 2), ['ADDR11'],       lambda self, il, imm: call_helper(il, CODE_ADDR(0x100, imm))],
        [('DIS', 1), ['TCNTI']],
        [('JT0', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'T0', 1)],
        [('CPL', 1), ['A'],             lambda self, il: il.set_reg(1, 'A', il.not_expr(1, il.reg(1, 'A')))],
        None,
        [('OUTL', 1), ['P1', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('OUTL', 1), ['P2', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        None,
        [('MOVD', 1), ['P4', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('MOVD', 1), ['P5', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('MOVD', 1), ['P6', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('MOVD', 1), ['P7', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        # 0x40-0x4f
        [('ORL', 1), ['A', '@R0'],      lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 0))))],
        [('ORL', 1), ['A', '@R1'],      lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 1))))],
        [('MOV', 1), ['A', 'T'],        lambda self, il: il.set_reg(1, 'A', il.reg(1, 'T'))],
        [('ORL', 2), ['A', '#IMM8'],    lambda self, il, imm: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), il.const(1, imm)))],
        [('JMP', 2), ['ADDR11'],        lambda self, il, imm: branch(il, CODE_ADDR(0x200, imm))],
        [('STRT', 1), ['CNT']],
        [('JNT1', 2), ['ADDR8'],        lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'T1', 0)],
        [('SWAP', 1), ['A'],            lambda self, il: il.set_reg(1, 'A', il.rotate_left(1, il.reg(1, 'A'), il.const(1, 4)))],
        [('ORL', 1), ['A', 'R0'],       lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 0)))],
        [('ORL', 1), ['A', 'R1'],       lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 1)))],
        [('ORL', 1), ['A', 'R2'],		lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 2)))],
        [('ORL', 1), ['A', 'R3'],		lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 3)))],
        [('ORL', 1), ['A', 'R4'],		lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 4)))],
        [('ORL', 1), ['A', 'R5'],		lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 5)))],
        [('ORL', 1), ['A', 'R6'],		lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 6)))],
        [('ORL', 1), ['A', 'R7'],		lambda self, il: il.set_reg(1, 'A', il.or_expr(1, il.reg(1, 'A'), self.wreg_get(il, 7)))],
        # 0x50-0x5f
        [('ANL', 1), ['A', '@R0'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 0))))],
        [('ANL', 1), ['A', '@R1'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 1))))],
        [('JB2', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 2)],
        [('ANL', 2), ['A', '#IMM8'],	lambda self, il, imm: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), il.const(1, imm)))],
        [('CALL', 2), ['ADDR11'],		lambda self, il, imm: call_helper(il, CODE_ADDR(0x200, imm))],
        [('STRT', 1), ['T'],            lambda self, il: il.reg(1, 'T')], # DUMMY
        [('JT1', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'T1', 1)],
        [('DA', 1), ['A']],
        [('ANL', 1), ['A', 'R0'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 0)))],
        [('ANL', 1), ['A', 'R1'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 1)))],
        [('ANL', 1), ['A', 'R2'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 2)))],
        [('ANL', 1), ['A', 'R3'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 3)))],
        [('ANL', 1), ['A', 'R4'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 4)))],
        [('ANL', 1), ['A', 'R5'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 5)))],
        [('ANL', 1), ['A', 'R6'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 6)))],
        [('ANL', 1), ['A', 'R7'],		lambda self, il: il.set_reg(1, 'A', il.and_expr(1, il.reg(1, 'A'), self.wreg_get(il, 7)))],
        # 0x60-0x6f
        [('ADD', 1), ['A', '@R0'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 0)), 'C'))],
        [('ADD', 1), ['A', '@R1'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 1)), 'C'))],
        [('MOV', 1), ['T', 'A'],		lambda self, il: il.set_reg(1, 'T', il.reg(1, 'A'))],
        None,
        [('JMP', 2), ['ADDR11'],        lambda self, il, imm: branch(il, CODE_ADDR(0x300, imm))],
        [('STOP', 1), ['TCNT']],
        None,
        [('RRC', 1), ['A'],             lambda self, il: il.set_reg(1, 'A', il.rotate_right_carry(1, il.reg(1, 'A'), il.const(1, 1), il.flag('CY'), 'C'))],
        [('ADD', 1), ['A', 'R0'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 0), 'C'))],
        [('ADD', 1), ['A', 'R1'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 1), 'C'))],
        [('ADD', 1), ['A', 'R2'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 2), 'C'))],
        [('ADD', 1), ['A', 'R3'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 3), 'C'))],
        [('ADD', 1), ['A', 'R4'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 4), 'C'))],
        [('ADD', 1), ['A', 'R5'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 5), 'C'))],
        [('ADD', 1), ['A', 'R6'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 6), 'C'))],
        [('ADD', 1), ['A', 'R7'],		lambda self, il: il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), self.wreg_get(il, 7), 'C'))],
        # 0x70-0x7f
        [('ADDC', 1), ['A', '@R0'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 0)), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', '@R1'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 1)), il.flag('CY'), 'C'))],
        [('JB3', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 3)],
        None,
        [('CALL', 2), ['ADDR11'],		lambda self, il, imm: call_helper(il, CODE_ADDR(0x300, imm))],
        [('ENT0', 1), ['CLK']],
        [('JF1', 2), ['ADDR8'],		    lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'F1', 1)],
        [('RR', 1), ['A'],		        lambda self, il: il.set_reg(1, 'A', il.rotate_right(1, il.reg(1, 'A'), il.const(1, 1)))],
        [('ADDC', 1), ['A', 'R0'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 0), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R1'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 1), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R2'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 2), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R3'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 3), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R4'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 4), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R5'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 5), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R6'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 6), il.flag('CY'), 'C'))],
        [('ADDC', 1), ['A', 'R7'],		lambda self, il: il.set_reg(1, 'A', il.add_carry(1, il.reg(1, 'A'), self.wreg_get(il, 7), il.flag('CY'), 'C'))],
        # 0x80-0x8f
        [('MOVX', 1), ['A', '@R0']],
        [('MOVX', 1), ['A', '@R1']],
        None,
        [('RET', 1), [],                lambda self, il: ret_helper(il, False)],
        [('JMP', 2), ['ADDR11'],        lambda self, il, imm: branch(il, CODE_ADDR(0x400, imm))],
        [('CLR', 1), ['F0'],            lambda self, il: il.set_flag('F0', il.const(0, 0))],
        [('JNI', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'INT', 0)],
        None,
        [('ORL', 2), ['BUS', '#IMM8']],
        [('ORL', 2), ['P1', '#IMM8']],
        [('ORL', 2), ['P2', '#IMM8']],
        None,
        [('ORLD', 1), ['P4', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('ORLD', 1), ['P5', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('ORLD', 1), ['P6', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('ORLD', 1), ['P7', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        # 0x90-0x9f
        [('MOVX', 1), ['@R0', 'A']],
        [('MOVX', 1), ['@R1', 'A']],
        [('JB4', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 4)],
        [('RETR', 1), [],               lambda self, il: ret_helper(il, True)],
        [('CALL', 2), ['ADDR11'],       lambda self, il, imm: call_helper(il, CODE_ADDR(0x400, imm))],
        [('CPL', 1), ['F0'],            lambda self, il: il.set_flag('F0', il.not_expr(0, il.flag('F0')))],
        [('JNZ', 2), ['ADDR8'],         lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'NZ')],
        [('CLR', 1), ['C'],             lambda self, il: il.set_flag('CY', il.const(0, 0))],
        [('ANL', 2), ['BUS', '#IMM8']],
        [('ANL', 2), ['P1', '#IMM8']],
        [('ANL', 2), ['P2', '#IMM8']],
        None,
        [('ANLD', 1), ['P4', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('ANLD', 1), ['P5', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('ANLD', 1), ['P6', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        [('ANLD', 1), ['P7', 'A'],      lambda self, il: il.reg(1, 'A')], # dummy read
        # 0xa0-0xaf
        [('MOV', 1), ['@R0', 'A'],      lambda self, il: il.store(1, self.wreg_get(il, 0), il.reg(1, 'A'))],
        [('MOV', 1), ['@R1', 'A'],      lambda self, il: il.store(1, self.wreg_get(il, 1), il.reg(1, 'A'))],
        None,
        [('MOVP', 1), ['A', '@A'],      lambda self, il: il.set_reg(1, 'A', il.load(1, il.or_expr(2, il.const(2, CODE_ADDR(il.current_address + 1, 0)), il.reg(1, 'A'))))],
        [('JMP', 2), ['ADDR11'],        lambda self, il, imm: branch(il, CODE_ADDR(0x500, imm))],
        [('CLR', 1), ['F1'],            lambda self, il: il.set_flag('F1', il.const(0, 0))],
        None,
        [('CPL', 1), ['C'],		        lambda self, il: il.set_flag('CY', il.not_expr(0, il.flag('CY')))],
        [('MOV', 1), ['R0', 'A'],		lambda self, il: self.wreg_set(il, 0, il.reg(1, 'A'))],
        [('MOV', 1), ['R1', 'A'],		lambda self, il: self.wreg_set(il, 1, il.reg(1, 'A'))],
        [('MOV', 1), ['R2', 'A'],		lambda self, il: self.wreg_set(il, 2, il.reg(1, 'A'))],
        [('MOV', 1), ['R3', 'A'],		lambda self, il: self.wreg_set(il, 3, il.reg(1, 'A'))],
        [('MOV', 1), ['R4', 'A'],		lambda self, il: self.wreg_set(il, 4, il.reg(1, 'A'))],
        [('MOV', 1), ['R5', 'A'],		lambda self, il: self.wreg_set(il, 5, il.reg(1, 'A'))],
        [('MOV', 1), ['R6', 'A'],		lambda self, il: self.wreg_set(il, 6, il.reg(1, 'A'))],
        [('MOV', 1), ['R7', 'A'],		lambda self, il: self.wreg_set(il, 7, il.reg(1, 'A'))],
        # 0xb0-0xbf
        [('MOV', 2), ['@R0', '#IMM8'],	lambda self, il, imm: il.store(1, self.wreg_get(il, 0), il.const(1, imm))],
        [('MOV', 2), ['@R1', '#IMM8'],	lambda self, il, imm: il.store(1, self.wreg_get(il, 1), il.const(1, imm))],
        [('JB5', 2), ['ADDR8'],		    lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 5)],
        [('JMPP', 1), ['@A'],		    lambda self, il: il.jump(il.or_expr(2, il.const(2, CODE_ADDR(il.current_address, 0)), il.reg(1, 'A')))], # FIXME: addr + 1?
        [('CALL', 2), ['ADDR11'],		lambda self, il, imm: call_helper(il, CODE_ADDR(0x500, imm))],
        [('CPL', 1), ['F1'],		    lambda self, il: il.set_flag('F1', il.not_expr(0, il.flag('F1')))],
        [('JF0', 2), ['ADDR8'],		    lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'F0', 1)],
        None,
        [('MOV', 2), ['R0', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 0, il.const(1, imm))],
        [('MOV', 2), ['R1', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 1, il.const(1, imm))],
        [('MOV', 2), ['R2', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 2, il.const(1, imm))],
        [('MOV', 2), ['R3', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 3, il.const(1, imm))],
        [('MOV', 2), ['R4', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 4, il.const(1, imm))],
        [('MOV', 2), ['R5', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 5, il.const(1, imm))],
        [('MOV', 2), ['R6', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 6, il.const(1, imm))],
        [('MOV', 2), ['R7', '#IMM8'],   lambda self, il, imm: self.wreg_set(il, 7, il.const(1, imm))],
        # 0xc0-0xcf
        None,
        None,
        None,
        None,
        [('JMP', 2), ['ADDR11'],		lambda self, il, imm: branch(il, CODE_ADDR(0x600, imm))],
        [('SEL', 1), ['RB0'],           lambda self, il: il.set_flag('BS', il.const(0, 0))],
        [('JZ', 2), ['ADDR8'],		    lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'Z')],
        [('MOV', 1), ['A', 'PSW'],		lambda self, il: il.set_reg(1, 'A', il.reg(1, 'PSW'))],
        [('DEC', 1), ['R0'],		    lambda self, il: self.wreg_set(il, 0, il.sub(1, self.wreg_get(il, 0), il.const(1, 1)))],
        [('DEC', 1), ['R1'],		    lambda self, il: self.wreg_set(il, 1, il.sub(1, self.wreg_get(il, 1), il.const(1, 1)))],
        [('DEC', 1), ['R2'],		    lambda self, il: self.wreg_set(il, 2, il.sub(1, self.wreg_get(il, 2), il.const(1, 1)))],
        [('DEC', 1), ['R3'],		    lambda self, il: self.wreg_set(il, 3, il.sub(1, self.wreg_get(il, 3), il.const(1, 1)))],
        [('DEC', 1), ['R4'],		    lambda self, il: self.wreg_set(il, 4, il.sub(1, self.wreg_get(il, 4), il.const(1, 1)))],
        [('DEC', 1), ['R5'],		    lambda self, il: self.wreg_set(il, 5, il.sub(1, self.wreg_get(il, 5), il.const(1, 1)))],
        [('DEC', 1), ['R6'],		    lambda self, il: self.wreg_set(il, 6, il.sub(1, self.wreg_get(il, 6), il.const(1, 1)))],
        [('DEC', 1), ['R7'],		    lambda self, il: self.wreg_set(il, 7, il.sub(1, self.wreg_get(il, 7), il.const(1, 1)))],
        # 0xd0-0xdf
        [('XRL', 1), ['A', '@R0'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 0))))],
        [('XRL', 1), ['A', '@R1'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), il.load(1, self.wreg_get(il, 1))))],
        [('JB6', 2), ['ADDR8'],		    lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 6)],
        [('XRL', 2), ['A', '#IMM8'],	lambda self, il, imm: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), il.const(1, imm)))],
        [('CALL', 2), ['ADDR11'],		lambda self, il, imm: call_helper(il, CODE_ADDR(0x600, imm))],
        [('SEL', 1), ['RB1'],           lambda self, il: il.set_flag('BS', il.const(0, 1))],
        None,
        [('MOV', 1), ['PSW', 'A'],      lambda self, il: il.set_reg(1, 'PSW', il.reg(1, 'A'))], # TODO: set/clear flags
        [('XRL', 1), ['A', 'R0'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 0)))],
        [('XRL', 1), ['A', 'R1'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 1)))],
        [('XRL', 1), ['A', 'R2'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 2)))],
        [('XRL', 1), ['A', 'R3'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 3)))],
        [('XRL', 1), ['A', 'R4'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 4)))],
        [('XRL', 1), ['A', 'R5'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 5)))],
        [('XRL', 1), ['A', 'R6'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 6)))],
        [('XRL', 1), ['A', 'R7'],		lambda self, il: il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), self.wreg_get(il, 7)))],
        # 0xe0-0xef
        None,
        None,
        None,
        [('MOVP3', 1), ['A', '@A'],		lambda self, il: il.set_reg(1, 'A', il.load(1, il.or_expr(2, il.const(2, CODE_ADDR(0x300, 0)), il.reg(1, 'A'))))],
        [('JMP', 2), ['ADDR11'],		lambda self, il, imm: branch(il, CODE_ADDR(0x700, imm))],
        [('SEL', 1), ['MB0'],           lambda self, il: il.set_flag('DBF', il.const(0, 0))],
        [('JNC', 2), ['ADDR8'],		   	lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'CY', 0)],
        [('RL', 1), ['A'],		       	lambda self, il: il.set_reg(1, 'A', il.rotate_left(1, il.reg(1, 'A'), il.const(1, 1)))],
        [('DJNZ', 2), ['R0', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 0)],
        [('DJNZ', 2), ['R1', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 1)],
        [('DJNZ', 2), ['R2', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 2)],
        [('DJNZ', 2), ['R3', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 3)],
        [('DJNZ', 2), ['R4', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 4)],
        [('DJNZ', 2), ['R5', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 5)],
        [('DJNZ', 2), ['R6', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 6)],
        [('DJNZ', 2), ['R7', 'ADDR8'],	lambda self, il, imm: self.djnz_helper(il, CODE_ADDR(il.current_address, imm), 7)],
        # 0xf0-0xff
        [('MOV', 1), ['A', '@R0'],		lambda self, il: il.set_reg(1, 'A', il.load(1, self.wreg_get(il, 0)))],
        [('MOV', 1), ['A', '@R1'],		lambda self, il: il.set_reg(1, 'A', il.load(1, self.wreg_get(il, 1)))],
        [('JB7', 2), ['ADDR8'],		   	lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'B', 7)],
        None,
        [('CALL', 2), ['ADDR11'],		lambda self, il, imm: call_helper(il, CODE_ADDR(0x700, imm))],
        [('SEL', 1), ['MB1'],           lambda self, il: il.set_flag('DBF', il.const(0, 1))],
        [('JC', 2), ['ADDR8'],		    lambda self, il, imm: cond_branch(il, CODE_ADDR(il.current_address, imm), 'CY', 1)],
        [('RLC', 1), ['A'],		        lambda self, il: il.set_reg(1, 'A', il.rotate_left_carry(1, il.reg(1, 'A'), il.const(1, 1), il.flag('CY')))],
        [('MOV', 1), ['A', 'R0'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 0))],
        [('MOV', 1), ['A', 'R1'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 1))],
        [('MOV', 1), ['A', 'R2'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 2))],
        [('MOV', 1), ['A', 'R3'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 3))],
        [('MOV', 1), ['A', 'R4'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 4))],
        [('MOV', 1), ['A', 'R5'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 5))],
        [('MOV', 1), ['A', 'R6'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 6))],
        [('MOV', 1), ['A', 'R7'],		lambda self, il: il.set_reg(1, 'A', self.wreg_get(il, 7))],
    ]

    def get_instruction_info(self, data, addr):

        # instruction lookup
        instruction = self.instructions[ord(data[0])]
        if instruction is None:
            return None

        (opcode, length) = instruction[0]

        result = InstructionInfo()
        result.length = length

        # add branches
        if opcode in ['RET', 'RETI', 'RETR']:
            result.add_branch(BranchType.FunctionReturn)
        elif opcode in ['JMP']:
            # TODO: memory bank selection
            result.add_branch(BranchType.UnconditionalBranch, CODE_ADDR((ord(data[0]) & 0xe0) << 3, ord(data[1])))
        elif opcode in ['JMPP']:
            result.add_branch(BranchType.UnresolvedBranch)
        elif opcode == 'DJNZ' or opcode[0] == 'J':
            # conditional branches
            result.add_branch(BranchType.TrueBranch, CODE_ADDR(addr, ord(data[1])))
            result.add_branch(BranchType.FalseBranch, addr + length)
        elif opcode == 'CALL':
            # TODO: memory bank selection
            result.add_branch(BranchType.CallDestination, CODE_ADDR((ord(data[0]) & 0xe0) << 3, ord(data[1])))
        elif opcode == 'SEL':
            # FIXME: fake branches to support bank switching
            if instruction[1][0] == 'RB0':
                result.add_branch(BranchType.UnconditionalBranch, addr + length, Architecture['{}_rb{}mb{}'.format(self.device, 0, self.mb)])
            elif instruction[1][0] == 'RB1':
                result.add_branch(BranchType.UnconditionalBranch, addr + length, Architecture['{}_rb{}mb{}'.format(self.device, 1, self.mb)])
            elif instruction[1][0] == 'MB0':
                result.add_branch(BranchType.UnconditionalBranch, addr + length, Architecture['{}_rb{}mb{}'.format(self.device, self.rb, 0)])
            elif instruction[1][0] == 'MB1':
                result.add_branch(BranchType.UnconditionalBranch, addr + length, Architecture['{}_rb{}mb{}'.format(self.device, self.rb, 1)])

        return result

    def get_instruction_text(self, data, addr):

        # instruction lookup
        instruction = self.instructions[ord(data[0])]
        if instruction is None:
            return None

        (opcode, length) = instruction[0]

        # opcode
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, '{:6}'.format(opcode))]

        # operands
        for operand in instruction[1]:
            # add a separator if needed
            if len(tokens) > 1:
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ',')]
            
            # append suffix for second bank working registers
            if self.rb == 1 and re.match('\@?R\d', operand) is not None:
                operand += '\''

            if operand == '#IMM8':
                immediate = ord(data[1])
                tokens += [InstructionTextToken(InstructionTextTokenType.IntegerToken, '#{:X}H'.format(immediate), immediate)]
            elif operand == 'ADDR8':
                address = (addr & 0xf00) | ord(data[1])
                tokens += [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '{:X}H'.format(address), CODE_ADDR(0, address))]
            elif operand == 'ADDR11':
                # TODO: memory bank selection
                address = ((ord(data[0]) & 0xe0) << 3) | ord(data[1])
                tokens += [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '{:X}H'.format(address), CODE_ADDR(0, address))]
            elif operand in self.regs:
                tokens += [InstructionTextToken(InstructionTextTokenType.RegisterToken, operand)]
            elif operand[0] == '@' and operand[1:] in self.regs:
                tokens += [InstructionTextToken(InstructionTextTokenType.InstructionToken, '@'), InstructionTextToken(InstructionTextTokenType.RegisterToken, operand[1:])]
            else:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, operand)]
                
        return tokens, length

    def get_instruction_low_level_il(self, data, addr, il):

        # instruction lookup
        instruction = self.instructions[ord(data[0])]
        if instruction is None:
            return None

        (opcode, length) = instruction[0]

        if len(instruction) == 3:
            # instructions are either one byte (opcode) or two bytes (opcode + immediate)
            if length == 1:
                il_instr = instruction[2](self, il)
            else:
                il_instr = instruction[2](self, il, ord(data[1]))

            if isinstance(il_instr, list):
                for i in [i for i in il_instr if i is not None]:
                    il.append(i)
            elif il_instr is not None:
                il.append(il_instr)
        else:
            il.append(il.unimplemented())

        return length

    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        if flag == 'CY':
            if op == LowLevelILOperation.LLIL_RRC:
                return il.and_expr(1, il.reg(1, operands[0]), il.const(1, 0x01))
            elif op == LowLevelILOperation.LLIL_RLC:
                return il.and_expr(1, il.reg(1, operands[0]), il.const(1, 0x80))
 
        return Architecture.perform_get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

    def wreg_set(self, il, reg, expr):
        if WREG_REG:
            il.append(il.set_reg(1, 'R{}'.format(reg) if self.rb == 0 else 'R{}\''.format(reg), expr))
        else:
            il.append(il.store(1, il.const_pointer(1, reg if self.rb == 0 else reg + 24), expr))

    def wreg_get(self, il, reg):
        if WREG_REG:
            return il.reg(1, 'R{}'.format(reg) if self.rb == 0 else 'R{}\''.format(reg))
        else:
            return il.load(1, il.const_pointer(1, reg if self.rb == 0 else reg + 24))

    def djnz_helper(self, il, addr, reg):

        # decrement the register
        self.wreg_set(il, reg, il.sub(1, self.wreg_get(il, reg), il.const(1, 1)))

        # try to find a label for the branch target
        taken = il.get_label_for_address(il.arch, addr)

        # create taken target
        taken_found = True
        if taken is None:
            taken = LowLevelILLabel()
            taken_found = False

        # create untaken target
        untaken_found = True
        untaken = il.get_label_for_address(il.arch, il.current_address + 2)
        if untaken is None:
            untaken = LowLevelILLabel()
            untaken_found = False

        # generate the conditional branch LLIL
        il.append(il.if_expr(il.compare_not_equal(1, self.wreg_get(il, reg), il.const(1, 0)), taken, untaken))

        # generate a jump to the branch target if a label couldn't be found
        if not taken_found:
            il.mark_label(taken)
            il.append(il.jump(il.const(2, addr)))

        # generate a label for the untaken branch
        if not untaken_found:
            il.mark_label(untaken)


class MCS48_804X(MCS48_Base):

    def __init__(self):
        super(MCS48_804X, self).__init__()

        # redefine register and memory bank switch instructions
        self.instructions[0xc5][2] = lambda self, il: self.bank_switch(il, 0, self.mb) # SEL RB0
        self.instructions[0xd5][2] = lambda self, il: self.bank_switch(il, 1, self.mb) # SEL RB1
        self.instructions[0xe5][2] = lambda self, il: self.bank_switch(il, self.rb, 0) # SEL MB0
        self.instructions[0xf5][2] = lambda self, il: self.bank_switch(il, self.rb, 1) # SEL MB1

    def bank_switch(self, il, rb, mb):
        target_arch = Architecture['{}_rb{}mb{}'.format(self.device, rb, mb)]
        target_addr = il.current_address + 1

        target_label = il.get_label_for_address(target_arch, target_addr)
        if target_label is None:
            il.set_current_address(target_addr, target_arch)
            il.append(il.jump(il.const(2, target_addr)))
        else:
            il.append(il.goto(target_label))

class MCS48_8049(MCS48_804X):
    device = '8049'
    rom_size = 2048
    ram_size = 128


class MCS48_8049_RB0MB0(MCS48_8049):
    name = '8049_rb0mb0'
    rb = 0
    mb = 0

class MCS48_8049_RB1MB0(MCS48_8049):
    name = '8049_rb1mb0'
    rb = 1
    mb = 0

class MCS48_8049_RB0MB1(MCS48_8049):
    name = '8049_rb0mb1'
    rb = 0
    mb = 1

class MCS48_8049_RB1MB1(MCS48_8049):
    name = '8049_rb1mb1'
    rb = 1
    mb = 1

class MCS48_8048(MCS48_804X):
    device = '8048'

class MCS48_802X(MCS48_Base):

    def __init__(self):
        super(MCS48_Base, self).__init__()

        # OUTL BUS,A
        # INS A,BUS
        # ENT0 CLK
        # JF1 address
        # CLR F1
        # CPL F1
        # JF0 address
        # SEL RB0
        # MOV A,PSW
        # SEL RB1
        # MOV PSW,A
        # MOVP3 A,@A
        # SEL MB0
        # SEL MB1
        for opcode in [0x02, 0x08, 0x75, 0x76, 0xa5, 0xb5, 0xb6, 0xc5, 0xc7, 0xd5, 0xd7, 0xe3, 0xe5, 0xf5]:
            self.instructions[opcode] = None

        # MOVX A,@Rr
        # CLR F0
        # JNI address
        # ORL BUS,#data
        # ORL Pp,#data
        for opcode in [0x80, 0x81, 0x85, 0x86, 0x88, 0x89, 0x8a]:
            self.instructions[opcode] = None

        # MOVX @Rr,A
        # RETR
        # CPL F0
        # ANL BUS,#data
        # ANL P1,#data
        # ANL P2,#data
        for opcode in [0x90, 0x91, 0x93, 0x95, 0x98, 0x99, 0x9a]:
            self.instructions[opcode] = None

        # DEC Rr
        for opcode in [0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf]:
            self.instructions[opcode] = None

        # JBb address
        for opcode in [0x12, 0x32, 0x52, 0x72, 0x92, 0xb2, 0xd2, 0xf2]:
            self.instructions[opcode] = None

        # 8021/8022 replacement instructions
        self.instructions[0x08] = [('IN', 1), ['A', 'P0']]
        self.instructions[0x90] = [('OUTL', 1), ['P0', 'A']]

class MCS48_8021(MCS48_802X):

    name = '8021'

    def __init__(self):
        super(MCS48_802X, self).__init__()

        # 8021 does not have the following instructions:
        # EN I
        # DIS I
        # EN TCNTI
        # JNT0 address
        # DIS TCNTI
        # JT0 address
        for opcode in [0x05, 0x15, 0x25, 0x26, 0x35, 0x36]:
            self.instructions[opcode] = None

class MCS48_8022(MCS48_802X):

    name = '8022'
    
    def __init__(self):
        super(MCS48_802X, self).__init__()

        # 8022 replacement instructions
        self.instructions[0x80] = [('RAD', 1), []]
        self.instructions[0x85] = [('SEL', 1), ['AN1']]
        self.instructions[0x93] = [('RETI', 1), []]
        self.instructions[0x95] = [('SEL', 1), ['AN0']]

class MCS48:
    # rom_size, ram_size, has_banks 
    devices = [
        # [MCS48_8021, '8021', 1024, 64, False],
        # [MCS48_8022, '8022', 2048, 64, False],
        # [MCS48_804X, '8048', 1024, 64, True],
        [MCS48_804X, '8049', 2048, 128, True],
    ]

    subclasses = {}

    @classmethod
    def register(cls):

        for device_class, device_name, device_rom, device_ram, device_banked in cls.devices:

            if device_banked:
                cls.subclasses[device_name] = []

                # device has register and memory banks
                for rb, mb in [[0,0], [1,0], [0,1], [1,1]]:
                    sc = type('MCS48_{}_RB{}MB{}'.format(device_name, rb, mb), (device_class,), {
                        'name': '{}_rb{}mb{}'.format(device_name, rb, mb),
                        'device':device_name,
                        'rom_size':device_rom,
                        'ram_size':device_ram,
                        'rb':rb,
                        'mb':mb
                    })
                    sc.register()

                    cls.subclasses[device_name] += [sc]
            else:
                device_class.name = device_name
                device_class.device = device_name
                device_class.rom_size = device_rom
                device_class.ram_size = device_ram

                device_class.register()
