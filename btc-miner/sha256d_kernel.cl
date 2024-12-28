#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define NONCE_OFFSET 72

// Rotate right
inline uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 Compression Function
void sha256_compression(uint* state, const uint* w, const __constant uint* K) {
    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint temp1 = h + s1 + ch + K[i] + w[i];
        uint s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// SHA-256 Main Function
void sha256(const char* input, int length, char* output, const __constant uint* K) {
    uint state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Padding and preprocessing
    uint w[64] = { 0 };
    for (int i = 0; i < length; i++) {
        w[i / 4] |= (uint)(unsigned char)input[i] << (24 - (i % 4) * 8);
    }
    w[length / 4] |= (uint)0x80 << (24 - (length % 4) * 8);
    w[15] = length * 8;

    // First compression
    sha256_compression(state, w, K);

    // Prepare for final block if needed
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    // Final compression
    sha256_compression(state, w, K);

    // Output the hash
    for (int i = 0; i < 8; i++) {
        output[i * 4] = (state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = state[i] & 0xFF;
    }
}

// Kernel Function
__kernel void sha256d_kernel(
    __global const char* blockHeaders,
    __global const ulong* nonces,
    __global ulong* results,
    ulong target,
    __constant uint* K) {

    int gid = get_global_id(0);  // Global thread ID
    __local char localHeader[80];  // Local memory for the header
    ulong nonce = nonces[gid];

    // Load block header into local memory
    for (int i = 0; i < 80; i++) {
        localHeader[i] = blockHeaders[gid * 80 + i];
    }

    // Insert nonce into the header
    for (int i = 0; i < 8; i++) {
        localHeader[NONCE_OFFSET + i] = (char)((nonce >> (i * 8)) & 0xFF);
    }

    // Compute double SHA-256
    char hash1[32];
    sha256(localHeader, 80, hash1, K);
    char hash2[32];
    sha256(hash1, 32, hash2, K);

    // Convert hash to numeric value
    ulong hashValue = 0;
    for (int i = 0; i < 8; i++) {
        hashValue |= (ulong)(unsigned char)hash2[i] << (i * 8);
    }

    // Check if hash meets target
    if (hashValue <= target) {
        atomic_min(&results[0], nonce);
    }
}
