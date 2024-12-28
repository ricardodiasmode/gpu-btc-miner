#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable  // Enable support for 64-bit integers

#define NONCE_OFFSET 72  // Adjust this depending on the header structure

// Manual memory copy (since memcpy is not available in OpenCL)
void copyBlockHeader(char* blockHeader, const char* blockHeaders, int i) {
    for (int j = 0; j < 80; j++) {
        blockHeader[j] = blockHeaders[i * 80 + j];
    }
}

// Convert the first 8 bytes of the hash to ulong (uint64_t equivalent)
ulong convertHashToUint64(char* hash) {
    ulong value = 0;
    for (int i = 0; i < 8; i++) {
        value |= (ulong)(unsigned char)hash[i] << (8 * i);
    }
    return value;
}

// Constants for SHA-256 (first 32 bits of the fractional parts of the square roots of the first 8 primes)
__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Rotate right
uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 compression function
void sha256_compression(uint* state, const uint* w) {
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

// SHA-256 function
void sha256(const char* input, int length, char* output) {
    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    uint state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Preprocessing (pad the message)
    char padded[64] = { 0 };
    int i;
    for (i = 0; i < length; i++) {
        padded[i] = input[i];
    }
    padded[length] = 0x80;  // Append '1' bit
    ulong bitLength = (ulong)length * 8;
    padded[56] = (bitLength >> 56) & 0xFF;
    padded[57] = (bitLength >> 48) & 0xFF;
    padded[58] = (bitLength >> 40) & 0xFF;
    padded[59] = (bitLength >> 32) & 0xFF;
    padded[60] = (bitLength >> 24) & 0xFF;
    padded[61] = (bitLength >> 16) & 0xFF;
    padded[62] = (bitLength >> 8) & 0xFF;
    padded[63] = bitLength & 0xFF;

    // Prepare the message schedule
    uint w[64] = { 0 };
    for (i = 0; i < 16; i++) {
        w[i] = ((uint)padded[i * 4] << 24) |
            ((uint)padded[i * 4 + 1] << 16) |
            ((uint)padded[i * 4 + 2] << 8) |
            ((uint)padded[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    // Perform the compression function
    sha256_compression(state, w);

    // Output the final hash
    for (i = 0; i < 8; i++) {
        output[i * 4] = (state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = state[i] & 0xFF;
    }
}


__kernel void sha256d_kernel(__global const char* blockHeaders, __global ulong* nonces, __global ulong* results, ulong target) {
    int i = get_global_id(0);
    char blockHeader[80];  // Adjust size for your header
    copyBlockHeader(blockHeader, blockHeaders, i);

    // Insert nonce into block header at the correct offset
    ulong nonce = nonces[i];
    blockHeader[NONCE_OFFSET] = (char)(nonce & 0xFF);  // Set the first byte of nonce (adjust for your format)
    blockHeader[NONCE_OFFSET + 1] = (char)((nonce >> 8) & 0xFF);
    blockHeader[NONCE_OFFSET + 2] = (char)((nonce >> 16) & 0xFF);
    blockHeader[NONCE_OFFSET + 3] = (char)((nonce >> 24) & 0xFF);
    blockHeader[NONCE_OFFSET + 4] = (char)((nonce >> 32) & 0xFF);
    blockHeader[NONCE_OFFSET + 5] = (char)((nonce >> 40) & 0xFF);
    blockHeader[NONCE_OFFSET + 6] = (char)((nonce >> 48) & 0xFF);
    blockHeader[NONCE_OFFSET + 7] = (char)((nonce >> 56) & 0xFF);

    // Compute double SHA-256 hash (replace this with actual SHA256 implementation)
    char hash1[32];
    sha256(blockHeader, 80, hash1);
    char hash2[32];
    sha256(hash1, 32, hash2);

    // Convert hash to numeric value
    ulong hashValue = convertHashToUint64(hash2);

    // Check if hash is below the target
    if (hashValue <= target) {
        results[0] = nonce; // Write the valid nonce to the results buffer
    }
}
