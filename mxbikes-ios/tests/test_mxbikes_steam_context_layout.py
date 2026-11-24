"""Synthetic metadata-only Steam context initializer layout inspector."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RCX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_steam_context_layout import inspect_context_init_data

BASE=0x140000000
class CPU:
    def __init__(self,argument=BASE+0x1000,data=None):
        self.argument=argument
        self.data=data if data is not None else struct.pack(
            "<QQQ",BASE+0x2000,0,0)
    def reg_read(self,reg):
        assert reg==UC_X86_REG_RCX
        return self.argument
    def mem_read(self,address,size):
        if address!=self.argument or size!=24:
            raise ValueError("unmapped")
        return self.data

class SteamContextLayoutTests(unittest.TestCase):
    def test_realistic_three_word_context_metadata_only(self):
        actual=inspect_context_init_data(CPU(),BASE,BASE+0x5000)
        self.assertTrue(actual["guest_argument_in_original_image"])
        self.assertEqual(actual["original_image_argument_rva"],"0x1000")
        self.assertEqual(actual["initializer_callback_rva"],"0x2000")
        self.assertTrue(actual["cached_interface_pointer_zero"])
        self.assertTrue(actual["counter_zero"])
        self.assertFalse(actual["interfaces_created_or_returned"])
        self.assertFalse(actual["steam_client_authenticated"])

    def test_missing_or_external_callback_or_bad_memory_is_not_fabricated(self):
        ext=inspect_context_init_data(CPU(data=struct.pack("<QQQ",
                                   0x700000000,123,0x800000000)),
                                   BASE,BASE+0x5000)
        self.assertTrue(ext["mapped_data_read"])
        self.assertFalse(ext["initializer_callback_in_original_image"])
        self.assertFalse(ext["counter_zero"])
        self.assertFalse(ext["cached_interface_pointer_zero"])
        invalid=inspect_context_init_data(CPU(argument=0x12),BASE,BASE+0x5000)
        self.assertFalse(invalid["guest_argument_in_original_image"])
        broken=inspect_context_init_data(CPU(data=b"invalid"),BASE,BASE+0x5000)
        self.assertFalse(broken["mapped_data_read"])
        self.assertIsNone(broken["counter_zero"])

if __name__=="__main__":
    unittest.main()
