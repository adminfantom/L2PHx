"""Decrypt L2 game bodies using the known XOR key.

Uses L2XorCipher to decrypt C2S game bodies captured by the proxy.
Must process packets IN ORDER to maintain correct counter state.
"""
import struct
import json
import sys
import os

# XOR key from proxy crypto state
XOR_KEY = bytes.fromhex("39fa711ef34a857d")
INTERLUDE_SUFFIX = bytes([0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97])

# Ertheia C2S opcode names
C2S_OPCODES = {
    0x00: "Logout", 0x01: "Attack", 0x03: "RequestStartPledgeWar",
    0x04: "RequestReplyStartPledgeWar", 0x05: "RequestStopPledgeWar",
    0x06: "RequestReplyStopPledgeWar", 0x07: "RequestSurrenderPledgeWar",
    0x08: "RequestReplySurrenderPledgeWar", 0x09: "RequestSetPledgeCrest",
    0x0B: "RequestGiveNickName", 0x0C: "CharacterCreate",
    0x0D: "CharacterDelete", 0x0E: "ProtocolVersion",
    0x0F: "MoveBackwardToLocation", 0x11: "EnterWorld",
    0x12: "CharacterSelect", 0x13: "NewCharacter",
    0x14: "RequestItemList", 0x16: "RequestUnEquipItem",
    0x17: "RequestDropItem", 0x19: "UseItem",
    0x1A: "TradeRequest", 0x1B: "AddTradeItem",
    0x1C: "TradeDone", 0x1F: "Action",
    0x22: "RequestLinkHtml", 0x23: "RequestBypassToServer",
    0x25: "RequestJoinParty", 0x26: "RequestJoinPledge",
    0x28: "RequestWithdrawalPledge", 0x2B: "AuthLogin",
    0x2F: "RequestCrystallizeItem", 0x30: "RequestPrivateStoreManageSell",
    0x31: "SetPrivateStoreListSell", 0x32: "AttackRequest",
    0x37: "RequestSellItem", 0x38: "RequestMagicSkillList",
    0x39: "RequestMagicSkillUse", 0x3A: "SendAppearing",
    0x3B: "SendWareHouseDepositList", 0x3C: "SendWareHouseWithDrawList",
    0x3D: "RequestShortCutReg", 0x3E: "RequestShortCutDel",
    0x3F: "RequestBuyItem", 0x40: "RequestDismissPledge",
    0x41: "RequestJoinPartyRoom", 0x44: "RequestPledgeInfo",
    0x46: "RequestGMList", 0x48: "ValidatePosition",
    0x49: "Say2", 0x4D: "RequestPledgeMemberList",
    0x57: "RequestSSQStatus", 0x58: "RequestPetGetItem",
    0x59: "RequestAllyInfo", 0x5B: "SetPrivateStoreListBuy",
    0x63: "RequestRestartPoint", 0x67: "RequestRecipeBookOpen",
    0x6B: "RequestRecipeShopManageList", 0x6C: "RequestRecipeShopMessageSet",
    0x73: "RequestRecipeShopMakeItem",
    0xB0: "MultiSellChoose",
    0xB1: "NetPing",
    0xD0: "RequestExPacket",
}

class L2XorCipher:
    def __init__(self, base_key: bytes):
        k = bytearray(base_key[:8])
        if len(k) < 8:
            k.extend(b'\x00' * (8 - len(k)))
        self.key = k + bytearray(INTERLUDE_SUFFIX)
        self.key_len = 15
        self._rotation_offset = 8

    def _rotate_key(self, size):
        off = self._rotation_offset
        v = struct.unpack_from("<I", self.key, off)[0]
        v = (v + size) & 0xFFFFFFFF
        struct.pack_into("<I", self.key, off, v)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt C2S packet (undo encrypt)."""
        size = len(data)
        if size == 0:
            return data
        buf = bytearray(data)
        kl = self.key_len
        for k in range(size - 1, 0, -1):
            buf[k] ^= self.key[k & kl] ^ buf[k - 1]
        buf[0] ^= self.key[0]
        self._rotate_key(size)
        return bytes(buf)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt C2S packet."""
        size = len(data)
        if size == 0:
            return data
        buf = bytearray(data)
        kl = self.key_len
        buf[0] ^= self.key[0]
        for i in range(1, size):
            buf[i] ^= self.key[i & kl] ^ buf[i - 1]
        self._rotate_key(size)
        return bytes(buf)

    def get_counter(self):
        return struct.unpack_from("<I", self.key, self._rotation_offset)[0]


def main():
    # Test: try to decrypt some known game bodies
    # These are the decoded game bodies from relay deobfuscation

    test_packets = [
        # (seq, encrypted_game_body_hex, description)
        # 0xCC packets (appeared to have plaintext-like data)
        (73, "cc06000067a14d0a03b1dc01b30000000000000000000000000000000000000004", "0xCC first"),
        (75, "cc06000067a14d0a03b1dc01b30000", "0xCC second"),
        (77, "cc", "0xCC short"),
        (79, "cc06000067a14d0a03b1dc01b30000000000000000000000000000000000000004000000d46770c379b7dc01000000", "0xCC long"),
        # 0x61 packets (position updates?)
        (123, "61d62b770cd62b61c4d62b44cdf55a2ddadc79099c705cc5adf4110f89d750", "0x61 first"),
        (131, "61d62b770cd62b61c4d62b44", "0x61 short"),
        # 0xC0 packets
        (51, "c0d92760606060ac66606007c12d6a63d1bc61d36060606060606060606060606060606060606064606060b40710a319d7bc616060606060606060", "0xC0 first"),
        # 0x4B packets
        (100, "4bb6c6fa4bb69dfc4bb6ea914bb6fc594bb6d95068c7b04741e49401edc15830698c92144acd753d9f956c9343931893df93b793b793", "0x4B first"),
        # 0x6D packets (latest periodic)
        (200, "6d6708693ee424c27c9256a6751c3e2c7e7322f0135778e5435b5db234c9", "0x6D first"),
    ]

    # Approach 1: Try decrypting with initial counter state (no counter tracking)
    print("=" * 80)
    print("APPROACH 1: Decrypt with INITIAL counter (no tracking)")
    print(f"XOR key: {XOR_KEY.hex()}")
    print(f"Initial counter: 0x{struct.unpack('<I', INTERLUDE_SUFFIX[:4])[0]:08X}")
    print("=" * 80)

    for seq, hex_data, desc in test_packets:
        cipher = L2XorCipher(XOR_KEY)  # Fresh cipher for each
        data = bytes.fromhex(hex_data)
        decrypted = cipher.decrypt(data)
        real_op = decrypted[0]
        op_name = C2S_OPCODES.get(real_op, f"0x{real_op:02X}")

        print(f"\nSeq {seq} ({desc}):")
        print(f"  Encrypted:  {hex_data[:60]}{'...' if len(hex_data) > 60 else ''}")
        print(f"  Decrypted:  {decrypted.hex()[:60]}{'...' if len(decrypted.hex()) > 60 else ''}")
        print(f"  Real opcode: 0x{real_op:02X} = {op_name}")
        if len(decrypted) > 1:
            print(f"  Data bytes:  {decrypted[1:17].hex()}")

    # Approach 2: Try simple XOR at position 0 only (check if opcode = enc ^ key[0])
    print("\n" + "=" * 80)
    print("APPROACH 2: Simple opcode XOR (enc[0] ^ key[0])")
    print(f"key[0] = 0x{XOR_KEY[0]:02X}")
    print("=" * 80)

    observed_ops = [0xCC, 0x61, 0xC0, 0x4B, 0x6D, 0x05, 0xDC, 0xAF, 0x94, 0xA9, 0xA1, 0x68, 0x58, 0x08, 0x39, 0x3B, 0x09, 0x02, 0x00]

    for enc_op in sorted(observed_ops):
        real_op = enc_op ^ XOR_KEY[0]
        op_name = C2S_OPCODES.get(real_op, f"0x{real_op:02X}")
        print(f"  Enc 0x{enc_op:02X} → Real 0x{real_op:02X} = {op_name}")

    # Approach 3: Try key[0] ^ INTERLUDE_SUFFIX interaction
    # The first byte: enc[0] = plain[0] ^ key[0]
    # key[0] = 0x39
    # If periodic opcode 0x61 is really ValidatePosition (0x48 in Ertheia):
    # 0x61 ^ key[0] = 0x61 ^ 0x39 = 0x58 → RequestPetGetItem? No...
    # If 0x61 is really NetPing (0xB1): 0x61 ^ 0x39 = 0x58 → no

    print("\n" + "=" * 80)
    print("APPROACH 3: Check if any decrypted opcode matches expected game behavior")
    print("=" * 80)
    print(f"Expected during idle: ValidatePosition(0x48), NetPing(0xB1)")
    print(f"Expected during login: EnterWorld(0x11), RequestItemList(0x14)")

    # For each known real opcode, what would its encrypted value be?
    key0 = XOR_KEY[0]  # 0x39
    important_ops = {
        0x19: "UseItem", 0x49: "Say2", 0xB0: "MultiSellChoose",
        0x48: "ValidatePosition", 0xB1: "NetPing", 0x11: "EnterWorld",
        0x14: "RequestItemList", 0x1F: "Action", 0xD0: "RequestExPacket",
        0x23: "RequestBypassToServer", 0x3B: "SendWareHouseDepositList",
        0x3C: "SendWareHouseWithDrawList",
    }

    print(f"\nWith key[0]=0x{key0:02X}, expected encrypted opcodes:")
    for real_op, name in sorted(important_ops.items()):
        enc_op = real_op ^ key0
        marker = " *** OBSERVED ***" if enc_op in observed_ops else ""
        print(f"  {name}(0x{real_op:02X}) → enc 0x{enc_op:02X}{marker}")


if __name__ == "__main__":
    main()
