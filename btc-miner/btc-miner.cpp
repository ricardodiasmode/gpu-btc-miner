#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>  // For OpenSSL 3.0
#include <regex>
#include <CL/cl.h>
#include <CL/cl_platform.h>
#include <fstream>

static constexpr uint8_t SUBSCRIBE_MESSAGE_ID = 1;
static constexpr uint8_t AUTHORIZE_MESSAGE_ID = 2;
static constexpr uint8_t SUBMIT_MESSAGE_ID = 3;
static constexpr char ACCOUNT_NAME[] = "RicardoRocky01";
static constexpr char ACCOUNT_PASSWORD[] = "123456";
static constexpr char WORKER_NAME[] = "RicardoRocky01.001";
static constexpr char POOL_URL[] = "bs.poolbinance.com";

static constexpr bool DEBUG_WORK_DATA = false;
static constexpr bool DEBUG_MINING = false;
static constexpr bool DEBUG_HASH_RATE = true;

uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Definições gerais
using namespace std;
namespace asio = boost::asio;
using json = nlohmann::json;

std::string IntToHex(uint64_t value, size_t width = 8) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0') << std::setw(width) << value;
    return stream.str();
}

std::string StringToHex(const std::string& data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

// Utility: Converts an integer to a hex string (little-endian by default)
std::string Int32ToHex(uint32_t value, bool littleEndian = true) {
    std::ostringstream oss;
    if (littleEndian) {
        for (int i = 0; i < 4; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (value & 0xFF);
            value >>= 8;
        }
    }
    else {
        oss << std::hex << std::setw(8) << std::setfill('0') << value;
    }
    return oss.str();
}

uint64_t stringToUint64(const std::string& hexString) {
    if (hexString.size() < 16) {
        throw std::invalid_argument("Hex string too short for uint64_t conversion.");
    }
    // Extract the first 16 characters of the hash
    std::string first16 = hexString.substr(0, 16);

    // Convert the first 16 characters to uint64_t
    uint64_t value = 0;
    std::istringstream iss(first16);
    iss >> std::hex >> value;

    if (iss.fail()) {
        throw std::invalid_argument("Invalid hex string for uint64_t conversion.");
    }

    return value;
}

std::string VecInt8ToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

void AppendLittleEndian(std::vector<uint8_t>& vec, uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        vec.push_back((value >> (i * 8)) & 0xFF);
    }
}

std::vector<uint8_t> HexStringToBytes(const std::string& hexStr) {
    if (hexStr.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even length");
    }

    std::vector<uint8_t> bytes(hexStr.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(std::stoi(hexStr.substr(i * 2, 2), nullptr, 16));
    }
    return bytes;
}

std::string sha256d(const std::string& data) {
    // Use RAII to ensure EVP context is cleaned up
    struct EVP_MD_CTX_Deleter {
        void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
    };
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // First SHA-256 pass
    unsigned char first_hash[EVP_MAX_MD_SIZE];
    unsigned int first_hash_len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), first_hash, &first_hash_len) != 1) {
        throw std::runtime_error("SHA-256 hashing failed in the first pass");
    }

    // Second SHA-256 pass
    unsigned char second_hash[EVP_MAX_MD_SIZE];
    unsigned int second_hash_len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), first_hash, first_hash_len) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), second_hash, &second_hash_len) != 1) {
        throw std::runtime_error("SHA-256 hashing failed in the second pass");
    }

    // Return as a hex string
    return StringToHex(std::string(reinterpret_cast<char*>(second_hash), second_hash_len));
}

cl_context CreateOpenCLContext(cl_device_id* device) {
    cl_int err;
    cl_uint platformCount;
    cl_platform_id platform;

    // Get the first available platform
    clGetPlatformIDs(1, &platform, &platformCount);

    // Get a GPU device from the platform
    clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, device, NULL);

    // Create a context with the selected device
    cl_context context = clCreateContext(NULL, 1, device, NULL, NULL, &err);
    if (err != CL_SUCCESS) {
        cerr << "Failed to create OpenCL context. Error: " << err << endl;
        exit(EXIT_FAILURE);
    }

    return context;
}

cl_command_queue CreateCommandQueue(cl_context context, cl_device_id device) {
    cl_int err;

    // Query devices in the context
    size_t deviceBufferSize;
    clGetContextInfo(context, CL_CONTEXT_DEVICES, 0, NULL, &deviceBufferSize);

    cl_command_queue queue = clCreateCommandQueueWithProperties(context, device, 0, &err);

    if (err != CL_SUCCESS) {
        cerr << "Failed to create OpenCL command queue. Error: " << err << endl;
        exit(EXIT_FAILURE);
    }

    return queue;
}

cl_program CreateProgram(cl_context context, const char* kernelFileName) {
    // Step 1: Read the kernel source from file
    std::ifstream kernelFile(kernelFileName, std::ios::in);
    if (!kernelFile.is_open()) {
        throw std::runtime_error("Failed to open kernel file: " + std::string(kernelFileName));
    }

    std::string kernelSource((std::istreambuf_iterator<char>(kernelFile)), std::istreambuf_iterator<char>());
    kernelFile.close();
    const char* kernelSourceCStr = kernelSource.c_str();
    size_t kernelSourceSize = kernelSource.size();

    // Step 2: Create the program from the kernel source
    cl_int err;
    cl_program program = clCreateProgramWithSource(context, 1, &kernelSourceCStr, &kernelSourceSize, &err);
    if (err != CL_SUCCESS) {
        throw std::runtime_error("Failed to create OpenCL program. Error code: " + std::to_string(err));
    }

    // Step 3: Get devices from the context
    size_t deviceBufferSize;
    clGetContextInfo(context, CL_CONTEXT_DEVICES, 0, nullptr, &deviceBufferSize);
    std::vector<cl_device_id> devices(deviceBufferSize / sizeof(cl_device_id));
    clGetContextInfo(context, CL_CONTEXT_DEVICES, deviceBufferSize, devices.data(), nullptr);

    // Step 4: Build the program
    err = clBuildProgram(program, devices.size(), devices.data(), nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // If build failed, print the build log for each device
        for (const auto& device : devices) {
            size_t logSize;
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &logSize);
            std::vector<char> buildLog(logSize);
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, logSize, buildLog.data(), nullptr);

            std::cerr << "Error building program on device: " << buildLog.data() << std::endl;
        }
        clReleaseProgram(program);
        throw std::runtime_error("Failed to build OpenCL program.");
    }

    return program;
}

struct work_data
{
    std::string job_id;
    std::string prev_block_hash;
    std::string generation_tx_part1;
    std::string generation_tx_part2;
    std::vector<std::string> merkle_branches;
    uint32_t block_version;
    uint32_t nBits;
    uint32_t nTime;
    bool clean_jobs;
    uint64_t difficulty;
    std::string ExtraNonce1;
    uint32_t ExtraNonce2;
    uint32_t ExtraNonceSize2;

    std::string remainder_data = "";

    std::string constructCoinbase() {
        return generation_tx_part1 + ExtraNonce1 + Int32ToHex(ExtraNonce2) + generation_tx_part2;
    }

    // Calculate the Merkle root
    std::string calculateMerkleRoot() {
        std::string hash = sha256d(constructCoinbase()); // Double SHA-256 of the coinbase

        // Iterate through the branches
        for (const auto& branch : merkle_branches) {
            if (branch.size() != 64 || !std::all_of(branch.begin(), branch.end(), ::isxdigit)) {
                throw std::invalid_argument("Invalid branch: must be a 64-character hexadecimal string");
            }

            // Combine hashes (big-endian ordering assumed for concatenation)
            std::string branch_bytes = StringToHex(branch);
            hash = sha256d(hash + branch_bytes);
        }

        return hash; // Final Merkle root
    }

    std::string SerializeHeader(uint32_t version, const std::string& previousHash, const std::string& merkleRoot,
        uint32_t nTime, uint32_t bits, uint32_t nonce) {
        // Validate input sizes
        if (previousHash.size() != 64 || !std::all_of(previousHash.begin(), previousHash.end(), ::isxdigit)) {
            throw std::invalid_argument("Invalid previous hash: must be a 64-character hexadecimal string");
        }
        if (merkleRoot.size() != 64 || !std::all_of(merkleRoot.begin(), merkleRoot.end(), ::isxdigit)) {
            throw std::invalid_argument("Invalid Merkle root: must be a 64-character hexadecimal string");
        }

        // Convert fields to bytes
        std::vector<uint8_t> headerBytes;
        headerBytes.reserve(80); // Bitcoin block headers are always 80 bytes

        // Append version (little-endian)
        AppendLittleEndian(headerBytes, version);

        // Append previous block hash (big-endian)
        auto prevHashBytes = HexStringToBytes(previousHash);
        headerBytes.insert(headerBytes.end(), prevHashBytes.rbegin(), prevHashBytes.rend()); // Reverse for big-endian

        // Append Merkle root (big-endian)
        auto merkleRootBytes = HexStringToBytes(merkleRoot);
        headerBytes.insert(headerBytes.end(), merkleRootBytes.rbegin(), merkleRootBytes.rend()); // Reverse for big-endian

        // Append nTime (little-endian)
        AppendLittleEndian(headerBytes, nTime);

        // Append bits (little-endian)
        AppendLittleEndian(headerBytes, bits);

        // Append nonce (little-endian)
        AppendLittleEndian(headerBytes, nonce);

        // Return the header as a hex string
        return VecInt8ToHex(headerBytes);
    }

    std::string GetHeader(uint32_t nonce) 
    {
        return SerializeHeader(block_version, prev_block_hash, calculateMerkleRoot(), nTime, nBits, nonce);
    }

    std::string AppendExtraNonce() {
        return ExtraNonce1 + IntToHex(ExtraNonce2);
    }

    work_data() = default;
};

static void send_request(asio::ip::tcp::socket& socket, const json& request) {
    std::string message = request.dump() + "\n";
    boost::asio::write(socket, boost::asio::buffer(message));
    std::cout << "Sent: " << message;
}

class Miner
{
    asio::ip::tcp::socket MinerSocket;
    work_data received_data;

public:

    bool isValidExtraNonce2(std::string extraNonce2) {
        return extraNonce2.size() <= size_t(4) * 2; // Each byte is 2 hex characters
    }

    Miner(asio::io_context& io_context) : MinerSocket(io_context)
    {
        try {
            boost::asio::ip::tcp::resolver resolver(io_context);
            auto endpoints = resolver.resolve(POOL_URL, "3333");
            boost::asio::connect(MinerSocket, endpoints);
            std::cout << "Connection successful on URL: " << POOL_URL << std::endl;
        }
        catch (const boost::system::system_error& e) {
            std::cerr << "Connection failed: " << e.what() << std::endl;
        }
    }

    ~Miner()
    {
        try {
            MinerSocket.close();
        }
        catch (const boost::system::system_error& e) {
            std::cerr << "Error closing socket: " << e.what() << '\n';
        }
    }

    void Subscribe()
    {
        json subscribe_request = {
            {"id", SUBSCRIBE_MESSAGE_ID},
            {"method", "mining.subscribe"},
            {"params", {WORKER_NAME}}
        };
        send_request(MinerSocket, subscribe_request);
    }

    void Authenticate()
    {
        json auth_request = {
            {"id", AUTHORIZE_MESSAGE_ID},
            {"method", "mining.authorize"},
            {"params", {ACCOUNT_NAME, ACCOUNT_PASSWORD}}
        };
        send_request(MinerSocket, auth_request);
    }

    void SendSolution(const uint32_t& nonce)
    {
        if (!isValidExtraNonce2(IntToHex(received_data.ExtraNonce2)))
        {
            cerr << "Submitted ExtraNonce2 is not valid. Request will probably fail." << endl;
        }

        json solution_request = {
                    {"id", SUBMIT_MESSAGE_ID},
                    {"method", "mining.submit"},
                    {"params", {WORKER_NAME, received_data.job_id, IntToHex(received_data.ExtraNonce2), received_data.nTime, Int32ToHex(nonce)}}
        };
        send_request(MinerSocket, solution_request);
    }

    void ParseExtraNoncesResponse(json j) {
        // Extra nonce message like: {"error":null,"id":1,"result":[[["mining.notify","0000473d1"],["mining.set_difficulty","0000473d2"]],"0000473d",8]}
        cout << "Parsing extra nonces..." << endl;
        received_data.ExtraNonce1 = j["result"][1];
        received_data.ExtraNonceSize2 = j["result"][2];
    }

    bool VerifyAuthorizeResponse(json j) {
        // Subscribe response message like: {"error":null,"id":2,"result":true}
        cout << "Verifying authorization..." << endl;
        if (!j["error"].is_null())
        {
            cerr << "Error on parse subscribe: " << j["error"] << endl;
            return false;
        }
        if (!j["result"])
        {
            cerr << "Error on parse subscribe: " << "result is false." << endl;
            return false;
        }
        cout << "Miner authorized." << endl;
        return true;
    }

    void ParseWorkData(json j) {
        if (DEBUG_WORK_DATA)
            cout << "Working with data: " << j << endl;

        // Getting data
        received_data.job_id = j["params"][0].get<std::string>();
        received_data.prev_block_hash = j["params"][1].get<std::string>();
        received_data.generation_tx_part1 = j["params"][2].get<std::string>();
        received_data.generation_tx_part2 = j["params"][3].get<std::string>();

        // Parse merkle branches
        for (const auto& branch : j["params"][4]) {
            received_data.merkle_branches.push_back(branch.get<std::string>());
        }

        // Parse other parameters
        received_data.block_version = std::stoul(j["params"][5].get<std::string>(), nullptr, 16); // Convert hex to uint32_t
        received_data.nBits = std::stoul(j["params"][6].get<std::string>(), nullptr, 16); // Convert hex to uint32_t
        received_data.nTime = std::stoul(j["params"][7].get<std::string>(), nullptr, 16); // Convert hex to uint32_t
        received_data.clean_jobs = j["params"][8].get<bool>();

        if (!received_data.job_id.empty()) {
            cout << "Received job_id: " << received_data.job_id << endl << endl;
        }
    }

    void ParseDifficultyData(json j) {
        received_data.difficulty = j["params"][0].get<uint64_t>();
    }

    bool ReceiveWorkData()
    {
        cout << "Receiving work data..." << endl;

        std::vector<char> buffer(2048);
        std::string accumulated_data = received_data.remainder_data;

        if (DEBUG_WORK_DATA)
            cout << "Last work data: " << accumulated_data << endl << endl;

        try {
            // Read data into the buffer
            size_t bytes_read = asio::read(MinerSocket, asio::buffer(buffer.data(), buffer.size()));

            // Ensure some data was read
            if (bytes_read == 0) {
                cerr << "No data received from miner socket." << endl;
                return false;
            }

            // Convert buffer to a string and append to accumulated data
            std::string work_data(buffer.data(), bytes_read);
            accumulated_data += work_data;

            if (DEBUG_WORK_DATA)
                cout << "Server response: " << accumulated_data << endl << endl;

            received_data.remainder_data = "";

            std::string line;
            std::stringstream ss(accumulated_data);
            while (std::getline(ss, line, '}')) {

                // Check if json_chunk is not empty and looks like a valid JSON object
                if (line.empty() || line == "null") {
                    return false;  // Skip invalid or empty chunks
                }

                try {
                    // Try parsing the current JSON chunk
                    json j = json::parse(line + '}');

                    if (j.contains("method"))
                    {
                        if (j["method"] == "mining.set_difficulty")
                        {
                            ParseDifficultyData(j);
                        }
                        else if (j["method"] == "mining.notify")
                        {
                            ParseWorkData(j);
                        }
                        else {
                            cout << "Could not understand data: " << line << endl;
                        }
                    }
                    else if (j.contains("error") && j["error"].is_null())
                    {
                        switch (j["id"].get<uint8_t>())
                        {
                        case SUBSCRIBE_MESSAGE_ID:
                            ParseExtraNoncesResponse(j);
                            break;
                        case AUTHORIZE_MESSAGE_ID:
                            if (!VerifyAuthorizeResponse(j))
                                return false;
                            break;
                        case SUBMIT_MESSAGE_ID:
                            cout << "Error on submitting response: " << j["error"][1] << endl << endl;
                            break;
                        default:
                            throw "Unexpected message id.";
                            break;
                        }
                    }
                    else if (j.contains("error") && !j["error"].is_null())
                    {
                        cout << "Remainder data parsed. We have an error: " << j["error"][1] << endl;
                        cout << "The error was given by message id: " << j["id"] << endl;

                        if (j["id"] == SUBMIT_MESSAGE_ID)
                            cout << "Means that our submit was ignored." << endl;

                        cout << endl;
                    }
                    else {
                        cout << "Could not understand data: " << line << endl;
                    }
                }
                catch (const std::exception& e) {
                    if (line.find("mining.notify") != std::string::npos)
                    {
                        if (DEBUG_WORK_DATA)
                            cout << "Parse remainder found. We are good to go: " << line << endl << endl;
                    }
                    received_data.remainder_data = line;

                    if (DEBUG_WORK_DATA)
                        cout << "Request remainder data: " << received_data.remainder_data << endl << endl;
                }
            }
        }
        catch (const std::exception& e) {
            cerr << "Error during work data reception: " << e.what() << endl;
            return false;
        }
        return true;
    }

    uint64_t calculateTarget(uint64_t difficulty) {
        uint64_t maxTarget = 0xFFFF000000000000; // High 64 bits of the full maximum target
        return maxTarget / difficulty;
    }

    void MineGPU(uint64_t target) {
        // Initialize OpenCL context, queue, and buffers
        cl_device_id device;
        cl_context context = CreateOpenCLContext(&device);
        cl_command_queue queue = CreateCommandQueue(context, device);
        cl_program program = CreateProgram(context, "sha256d_kernel.cl");

        cl_int err = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
        if (err != CL_SUCCESS) {
            // Handle the error, print the error log for debugging
            size_t logSize;
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &logSize);
            char* log = new char[logSize];
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, logSize, log, NULL);
            std::cerr << "OpenCL Program Build Log: " << log << std::endl;
            delete[] log;
        }

        cl_kernel kernel = clCreateKernel(program, "sha256d_kernel", NULL);

        // Allocate buffers
        size_t batchSize = 1024*2; // Workload per thread
        size_t nonceBatchSize = 32*32*32*16; // Number of nonces per thread
        size_t totalNonces = batchSize * nonceBatchSize;

        char* blockHeaders = new char[80 * batchSize];
        uint64_t* results = new uint64_t[1];
        results[0] = 0;

        cl_mem clBlockHeaders = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(char) * 80 * batchSize, NULL, NULL);
        cl_mem clResults = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(uint64_t), NULL, NULL);
        cl_mem d_K = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
            64 * sizeof(uint32_t), K, nullptr);
        uint64_t* nonces = new uint64_t[totalNonces];
        cl_mem clNonces = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
            sizeof(uint64_t) * totalNonces, nonces, &err);
        if (err != CL_SUCCESS) {
            std::cerr << "Error creating buffer for nonces: " << err << std::endl;
            return;
        }

        // Timer for hash rate calculation
        std::chrono::time_point<std::chrono::system_clock> StartTime = std::chrono::system_clock::now();
        uint64_t nHashes = 0;

        while (true) {
            // Fill block headers
            for (size_t i = 0; i < batchSize; i++) {
                memcpy(blockHeaders + i * 80, received_data.GetHeader(nHashes + i * nonceBatchSize).c_str(), 80);
            }

            // Write headers to GPU (only once per batch)
            clEnqueueWriteBuffer(queue, clBlockHeaders, CL_TRUE, 0, sizeof(char) * 80 * batchSize, blockHeaders, 0, NULL, NULL);

            // Set kernel arguments
            cl_int err;
            err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &clBlockHeaders);
            if (err != CL_SUCCESS) {
                std::cerr << "Error setting kernel argument 0: " << err << std::endl;
            }

            err = clSetKernelArg(kernel, 1, sizeof(cl_mem), &clNonces);
            if (err != CL_SUCCESS) {
                std::cerr << "Error setting kernel argument 1: " << err << std::endl;
            }

            err = clSetKernelArg(kernel, 2, sizeof(cl_mem), &clResults);
            if (err != CL_SUCCESS) {
                std::cerr << "Error setting kernel argument 2: " << err << std::endl;
            }

            err = clSetKernelArg(kernel, 3, sizeof(uint64_t), &target);
            if (err != CL_SUCCESS) {
                std::cerr << "Error setting kernel argument 3: " << err << std::endl;
            }

            err = clSetKernelArg(kernel, 4, sizeof(cl_mem), &d_K);
            if (err != CL_SUCCESS) {
                std::cerr << "Error setting kernel argument 4: " << err << std::endl;
            }

            err = clSetKernelArg(kernel, 5, sizeof(uint64_t), &nonceBatchSize);
            if (err != CL_SUCCESS) {
                std::cerr << "Error setting kernel argument 5: " << err << std::endl;
            }

            // Adjust global and local work size based on GPU capabilities
            size_t globalWorkSize = batchSize;
            size_t localWorkSize = 256; // Optimize for GPU hardware (e.g., NVIDIA warp size)

            // Launch the kernel
            err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &globalWorkSize, &localWorkSize, 0, NULL, NULL);
            if (err != CL_SUCCESS) {
                printf("Error enqueuing kernel: %d\n", err);
            }

            // Asynchronously read results from GPU
            cl_event read_event;
            err = clEnqueueReadBuffer(queue, clResults, CL_FALSE, 0, sizeof(uint64_t), results, 0, NULL, &read_event);
            if (err != CL_SUCCESS) {
                std::cerr << "Error on enqueue kernel buffer: " << err << std::endl;
            }

            // Wait for the result and check if a solution is found
            err = clWaitForEvents(1, &read_event);
            if (err != CL_SUCCESS) {
                std::cerr << "Error on wait kernel event: " << err << std::endl;
            }

            if (results[0] != 0) {
                std::cout << "Solution found: Nonce = " << results[0] << std::endl;
                SendSolution(results[0]);
                break; // Exit after finding a solution
            }

            if (nHashes + totalNonces < nHashes) {
                cout << "Integer overflow detected!" << endl;
                break;
            }
            nHashes += totalNonces; // Increment total number of hashes

            // Log hash rate every 10 seconds
            auto Now = std::chrono::system_clock::now();
            auto DeltaTime = std::chrono::duration_cast<std::chrono::seconds>(Now - StartTime).count();
            if (DeltaTime > 0 && nHashes % (10 * totalNonces) == 0) {
                std::cout << "GPU made " << nHashes << " hashes in " << DeltaTime << " seconds ("
                    << nHashes / DeltaTime << " H/s)." << std::endl;
            }
        }

        auto Now = std::chrono::system_clock::now();
        auto DeltaTime = std::chrono::duration_cast<std::chrono::seconds>(Now - StartTime).count();
        std::cout << "GPU made " << nHashes << " hashes in " << DeltaTime << " seconds." << std::endl;

        // Clean up
        delete[] blockHeaders;
        delete[] results;
        delete[] nonces;
        clReleaseMemObject(clNonces);
        clReleaseMemObject(clBlockHeaders);
        clReleaseMemObject(clResults);
        clReleaseKernel(kernel);
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
    }


    void StartMiner() {
        while (true) {
            if (!ReceiveWorkData()) {
                cout << "Miner failed to receive work data." << endl << endl;
                break;
            }

            // Calculate the target based on the difficulty
            uint64_t target = calculateTarget(received_data.difficulty);

            cout << "--- Starting POW. ---" << endl;
            MineGPU(target);
            cout << "--- POW finished. ---" << endl << endl;
        }
    }
};

int main() {
    try {
        cout << "Initializing miner..." << endl << endl;
        asio::io_context io_context;
        Miner CurrentMiner(io_context);
        
        cout << "Miner initialized. Subscribing..." << endl << endl;
        CurrentMiner.Subscribe();

        cout << "Miner subscribed. Authenticating..." << endl << endl;
        CurrentMiner.Authenticate();

        cout << "Miner authenticated, start mining..." << endl << endl;
        CurrentMiner.StartMiner();
    }
    catch (std::exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
