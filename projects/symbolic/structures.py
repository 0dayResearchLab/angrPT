#  structures.py
#
#  Copyright 2018 Spencer McIntyre <zeroSteiner@gmail.com>
#  Copyright 2020 Namjun Jo <kirasys@theori.io>
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import collections

class SymbolicStructureBase(object):
    FieldDetails = collections.namedtuple('FieldDetails', ('name', 'size', 'offset', 'ctype'))

    def __init__(self, state, address):
        self.state = state
        self.address = address
        self.fields = collections.OrderedDict()
        for spec in self._fields_:
            spec = self.FieldDetails(*spec)
            symbol = state.solver.BVS(spec.name, spec.size * 8)
            # setattr(self, name, symbol)
            type_ = "uint{0}_t".format(spec.size * 8)
            setattr(state.mem[address + spec.offset], type_, symbol)
            self.fields[spec.name] = symbol

    def eval_field(self, field_name, state=None):
        state = state or self.state
        symbol = self.fields[field_name]
        return state.solver.eval(symbol)

    def get_field_details(self, field_name):
        for spec in self._fields_:
            spec = self.FieldDetails(*spec)
            if spec.name == field_name:
                return spec
        raise RuntimeError('invalid field: ' + field_name)

    def read_field(self, field_name, state=None):
        state = state or self.state
        spec = self.get_field_details(field_name)
        return getattr(state.mem[self.address + spec.offset], "uint{0}_t".format(spec.size * 8))

    def read_field_single_valued(self, field_name, state=None):
        state = state or self.state
        field = self.read_field(field_name, state=state)
        if not state.solver.single_valued(field.resolved):
            return None
        return field.concrete

    def pp(self, state=None):
        state = state or self.state
        print("0x{0:08x} {1}".format(self.address, self.__class__.__name__))
        for spec in self._fields_:
            spec = self.FieldDetails(*spec)
            symbol = self.fields[spec.name]
            if state.solver.unique(symbol):
                value = "0x{0:x}".format(state.solver.eval(symbol))
            else:
                value = '???'
            print("0x{0:08x}     {1: <20} {2}".format(self.address + spec.offset, spec.name, value))

    def to_dict(self, state=None):
        state = state or self.state
        fields = []
        for spec in self._fields_:
            spec = self.FieldDetails(*spec)
            field = self.read_field(spec.name, state=state)
            fields.append({
                'name': spec.name,
                'type': spec.ctype,
                'value': None if field.resolved.symbolic else field.concrete
            })
        return {'name': self.__class__.__name__, 'fields': fields}

class DRIVER_OBJECT(SymbolicStructureBase):
    _fields_ = (
        ('Type',                     2, 0x00, 'uint16_t Type'),
        ('Size',                     2, 0x02, 'uint16_t Size'),
        ('DeviceObject',             8, 0x08, 'void* DeviceObject'),
        ('Flags',                    8, 0x10, 'uint64_t Flags'),
        ('DriverStart',              8, 0x18, 'void* DriverStart'),
        ('DriverSize',               8, 0x20, 'uint64_t DriverSize'),
        ('DriverSection',            8, 0x28, 'void* DriverSection'),
        ('DriverExtension',          8, 0x30, 'void* DriverExtension'),
        ('DriverName.Length',        2, 0x38, 'uint16_t Length'),
        ('DriverName.MaximumLength', 2, 0x3a, 'uint16_t MaximumLength'),
        ('DriverName.Buffer',        8, 0x40, 'uint16_t* Buffer'),
        # UNICODE_STRING DriverName;
        ('HardwareDatabase',         8, 0x48, 'void* HardwareDatabase'),
        ('FastIoDispatch',           8, 0x50, 'void* FastIoDispatch'),
        ('DriverInit',               8, 0x58, 'void* DriverInit'),
        ('DriverStartIo',            8, 0x60, 'void* DriverStartIo'),
        ('DriverUnload',             8, 0x68, 'void* DriverUnload'),
        # void* MajorFunction[28];
    )

class IO_STACK_LOCATION(SymbolicStructureBase):
    _fields_ = (
        ('MajorFunction',      1, 0x00, 'uint8_t MajorFunction'),
        ('MinorFunction',      1, 0x01, 'uint8_t MinorFunction'),
        ('Flags',              1, 0x02, 'uint8_t Flags'),
        ('Control',            1, 0x03, 'uint8_t Control'),
        ('OutputBufferLength', 4, 0x08, 'uint32_t OutputBufferLength'),
        ('InputBufferLength',  4, 0x10, 'uint32_t InputBufferLength'),
        ('IoControlCode',      4, 0x18, 'uint32_t IoControlCode'),
        ('Type3InputBuffer',   8, 0x20, 'void* Type3InputBuffer'),
        ('DeviceObject',       8, 0x28, 'void* DeviceObject'),
        ('FileObject',         8, 0x30, 'void* FileObject'),
        ('CompletionRoutine',  8, 0x38, 'void* CompletionRoutine'),
        ('Context',            8, 0x40, 'void* Context'),
    )

class IRP(SymbolicStructureBase):
    _fields_ = (
        ('Type',                              2, 0x00, 'uint16_t Type'),
        ('Size',                              2, 0x02, 'uint16_t Size'),
        ('AllocationProcessorNumber',         2, 0x04, 'uint16_t AllocationProcessorNumber'),
        ('MdlAddress',                        8, 0x08, 'void* MdlAddress'),
        ('Flags',                             8, 0x10, 'uint64_t Flags'),
        ('AssociatedIrp.SystemBuffer',        8, 0x18, 'void* SystemBuffer'),
        ('IoStatus.Status',                   4, 0x30, 'uint32_t Status'),
        ('IoStatus.Information',              8, 0x38, 'uint64_t Information'),
        ('RequestorMode',                     1, 0x40, 'int8_t RequestorMode'),
        ('PendingReturned',                   1, 0x41, 'uint8_t PendingReturned'),
        ('StackCount',                        1, 0x42, 'int8_t StackCount'),
        ('CurrentLocation',                   1, 0x43, 'int8_t CurrentLocation'),
        ('Cancel',                            1, 0x44, 'uint8_t Cancel'),
        ('CancelIrql',                        1, 0x45, 'uint8_t CancelIrql'),
        ('ApcEnvironment',                    1, 0x46, 'int8_t ApcEnvironment'),
        ('AllocationFlags',                   1, 0x47, 'uint8_t AllocationFlags'),
        ('UserIosb',                          8, 0x48, 'void* UserIosb'),
        ('UserEvent',                         8, 0x58, 'void* UserEvent'),
        ('CancelRoutine',                     8, 0x58, 'void* CancelRoutine'),
        ('Tail.Overlay.CurrentStackLocation', 8, 0xb8, 'void* CurrentStackLocation'),
    )