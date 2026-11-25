import struct
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxb_gl_callsite import prove_callsite

BASE = 0x140000000
PC = 0x500000000
SLOT = 0x300
LIB = 'OPENGL32.dll'
SYM = 'glDrawElements'


class Image:
    sections = [('text', 0x200, 0x100, 0x200, 0, 0x20000000),
                ('iat', 0x100, 0x300, 0x100, 0, 0)]

    def __init__(self):
        self.disk = bytearray(0x400)
        self.guest = bytearray(self.disk)
        self.guest[SLOT:SLOT+8] = struct.pack('<Q', PC)

    def read_rva(self, rva, size):
        return self.disk[rva:rva+size]

    def read_guest(self, va, size):
        rva = va - BASE
        return self.guest[rva:rva+size]

    def code(self, rva, data):
        self.disk[rva:rva+len(data)] = data
        self.guest[rva:rva+len(data)] = data


class CallsiteTests(unittest.TestCase):
    def setUp(self):
        self.pe = Image()
        self.iat = {SLOT: (LIB.lower(), SYM)}

    def prove(self, ret, pc=PC, symbol=SYM):
        return prove_callsite(self.pe, self.iat, BASE, self.pe.read_guest,
                              BASE + ret, pc, LIB, symbol)

    def direct(self, call=0x120):
        self.pe.code(call, b'\xff\x15' + struct.pack('<i', SLOT-call-6))
        return call + 6

    def thunk(self):
        call, target = 0x180, 0x140
        self.pe.code(call, b'\xe8' + struct.pack('<i', target-call-5))
        self.pe.code(target, b'\xff\x25' + struct.pack('<i', SLOT-target-6))
        return call + 5

    def test_direct(self):
        self.assertEqual(self.prove(self.direct())['call_form'], 'rip_relative_iat_call')

    def test_backward_relative_thunk(self):
        row = self.prove(self.thunk())
        self.assertEqual(row['call_form'], 'direct_call_iat_thunk')
        self.assertEqual(row['original_thunk_rva'], '0x140')

    def test_live_target_mismatch(self):
        self.assertIsNone(self.prove(self.direct(), PC+16))

    def test_wrong_symbol(self):
        self.assertIsNone(self.prove(self.direct(), symbol='glBegin'))

    def test_changed_guest_instruction(self):
        ret = self.direct()
        self.pe.guest[ret-6] = 0x90
        self.assertIsNone(self.prove(ret))

    def test_changed_thunk(self):
        ret = self.thunk()
        self.pe.guest[0x140] = 0x90
        self.assertIsNone(self.prove(ret))

    def test_non_executable_call(self):
        self.assertIsNone(self.prove(self.direct(0x380)))

    def test_unsupported_thunk_chain(self):
        ret = self.thunk()
        self.pe.code(0x140, b'\xe9' + struct.pack('<i', 0x160-0x145))
        self.pe.code(0x160, b'\xff\x25' + struct.pack('<i', SLOT-0x166))
        self.assertIsNone(self.prove(ret))

    def test_unmapped_iat(self):
        ret = self.direct()
        self.pe.guest = self.pe.guest[:SLOT]
        self.assertIsNone(self.prove(ret))


if __name__ == '__main__':
    unittest.main()
