
from binaryninja.architecture import Architecture
from binaryninja.platform import Platform
from binaryninja.callingconvention import CallingConvention

from architecture import MCS48
from binaryview import Native

class DefaultCallingConvention(CallingConvention):
    int_arg_regs = []
    int_return_reg = 'A'

MCS48.register()    
Native.register()

for arch_name in ['8049_rb0mb0']: #, '8049_rb1mb0', '8049_rb0mb1', '8049_rb1mb1']:
    target_arch = Architecture[arch_name]
    target_arch.register_calling_convention(DefaultCallingConvention(target_arch, 'default'))
    target_arch.standalone_platform.default_calling_convention = target_arch.calling_conventions['default']

# class MCS48Platform(Platform):
#     name = '8049_rb0mb0'

# arch = Architecture['8049_rb0mb0']
# mcs48 = MCS48Platform(arch)
# mcs48.default_calling_convention = arch.calling_conventions['default']
# mcs48.register('mcs48')
