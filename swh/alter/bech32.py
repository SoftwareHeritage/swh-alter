# Copyright (c) 2017, 2020 Pieter Wuille
#               2023 The Software Heritage developers
#
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32/Bech32m and segwit addresses."""


from enum import Enum
from typing import List, Optional, Tuple


class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""

    BECH32 = 1
    BECH32M = 2


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def convert_bits(
    data: List[int], from_bits: int, to_bits: int, pad: bool = False
) -> List[int]:
    assert from_bits <= 8 and to_bits <= 8 and from_bits > 0 and to_bits > 0
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits) > 0:
            raise ValueError("Out of range")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("Padding is disabled but bits are left unwritten…")
    return ret


def bech32_polymod(values: List[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: List[int]) -> Optional[Encoding]:
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None


def bech32_create_checksum(hrp: str, data: List[int], spec: Encoding) -> List[int]:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: List[int], spec: Encoding) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(bech: str) -> Tuple[str, List[int], Encoding]:
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        raise ValueError("Non alphanumeric characters")
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("Mixed case is not allowed")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        raise ValueError("Unable to find separator")
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        raise ValueError("Characters outside the Bech32 character set")
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        raise ValueError("Checksum error")
    return (hrp, data[:-6], spec)
