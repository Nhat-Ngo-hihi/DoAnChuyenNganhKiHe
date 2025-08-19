# huffman.py
from collections import Counter, namedtuple
import heapq

Node = namedtuple("Node", ["char", "freq", "left", "right"])

def build_tree(data):
    if not data:
        return None
    freq = Counter(data)
    heap = [[freq[char], Node(char, freq[char], None, None)] for char in freq]
    heapq.heapify(heap)
    while len(heap) > 1:
        lo = heapq.heappop(heap)
        hi = heapq.heappop(heap)
        merged = Node(None, lo[0] + hi[0], lo[1], hi[1])
        heapq.heappush(heap, [merged.freq, merged])
    return heap[0][1]

def build_codes(node, prefix="", codebook=None):
    if codebook is None:
        codebook = {}
    if node is None:
        return codebook
    if node.char is not None:
        codebook[node.char] = prefix
    else:
        build_codes(node.left, prefix + "0", codebook)
        build_codes(node.right, prefix + "1", codebook)
    return codebook

def huffman_compress(data):
    if not data:
        return b'', None, 0
    tree = build_tree(data)
    codes = build_codes(tree)
    encoded = "".join(codes[byte] for byte in data)
    padding_bits = (8 - len(encoded) % 8) % 8
    encoded += "0" * padding_bits
    b = bytearray()
    for i in range(0, len(encoded), 8):
        b.append(int(encoded[i:i+8], 2))
    return bytes(b), tree, padding_bits

def huffman_decompress(data, tree, padding_bits):
    if not data or tree is None:
        return b''
    bit_str = "".join(f"{byte:08b}" for byte in data)
    if padding_bits:
        bit_str = bit_str[:-padding_bits]
    result = bytearray()
    node = tree
    for bit in bit_str:
        node = node.left if bit == "0" else node.right
        if node.char is not None:
            result.append(node.char)
            node = tree
    return bytes(result)
