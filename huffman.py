# huffman.py
from collections import Counter
import heapq

class Node:
    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char = char
        self.freq = freq
        self.left = left
        self.right = right
    def __lt__(self, other):
        return self.freq < other.freq

def build_tree(data: bytes):
    freq = Counter(data)
    heap = [Node(ch, fr) for ch, fr in freq.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        lo = heapq.heappop(heap)
        hi = heapq.heappop(heap)
        merged = Node(None, lo.freq + hi.freq, lo, hi)
        heapq.heappush(heap, merged)
    return heap[0] if heap else None

def build_codes(node, prefix="", codebook=None):
    if codebook is None:
        codebook = {}
    if not node:
        return codebook
    if node.char is not None:
        codebook[node.char] = prefix or "0"  # nếu chỉ có 1 ký tự
    else:
        build_codes(node.left, prefix + "0", codebook)
        build_codes(node.right, prefix + "1", codebook)
    return codebook

def huffman_compress(data: bytes):
    if not data:
        return b"", {}, 0
    tree = build_tree(data)
    codes = build_codes(tree)

    encoded = "".join(codes[b] for b in data)
    padding_bits = (8 - len(encoded) % 8) % 8
    encoded += "0" * padding_bits

    out = bytearray()
    for i in range(0, len(encoded), 8):
        out.append(int(encoded[i:i+8], 2))

    return bytes(out), codes, padding_bits

def huffman_decompress(data: bytes, codes: dict, padding_bits: int):
    if not data or not codes:
        return b""

    # đảo ngược codebook
    rev = {v: k for k, v in codes.items()}

    bit_str = "".join(f"{b:08b}" for b in data)
    if padding_bits:
        bit_str = bit_str[:-padding_bits]

    result = bytearray()
    buf = ""
    for bit in bit_str:
        buf += bit
        if buf in rev:
            result.append(rev[buf])
            buf = ""
    return bytes(result)
