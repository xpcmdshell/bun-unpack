"""Base64 VLQ as used by source-map `mappings` fields.

This is not ordinary Base64: each value is zigzag-encoded into 5-bit groups with
a continuation bit, so `base64` cannot encode or decode it. Every caller in this
package shares this one codec.
"""

from __future__ import annotations

from bun_unpack.errors import BunUnpackError

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
DECODE = {character: index for index, character in enumerate(ALPHABET)}
MAPPING_BYTES = frozenset((ALPHABET + ";,").encode("ascii"))


def encode(value: int) -> str:
    bits = (-value * 2 + 1) if value < 0 else value * 2
    output = []
    while bits >= 32:
        output.append(ALPHABET[(bits & 31) | 32])
        bits >>= 5
    output.append(ALPHABET[bits])
    return "".join(output)


def decode_segment(segment: str) -> list[int]:
    values: list[int] = []
    value = shift = 0
    for character in segment:
        try:
            digit = DECODE[character]
        except KeyError as error:
            raise BunUnpackError("Invalid base64 VLQ mapping character") from error
        value |= (digit & 31) << shift
        if digit & 32:
            shift += 5
            if shift > 35:
                raise BunUnpackError("Oversized VLQ mapping field")
        else:
            values.append(-(value >> 1) if value & 1 else value >> 1)
            value = shift = 0
    if shift:
        raise BunUnpackError("Truncated VLQ mapping field")
    return values
