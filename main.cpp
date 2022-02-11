#include <iostream>
#include <vector>
#include <json11.hpp>
#include <chrono>
#include <cstring>
#include <zconf.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>

#define BASE_URL "http://hashcrack.algonics.net"
#define WORKER_ID_K "wid"
#define CHALLENGE_ID_K "cid"
#define SALT_K "salt"
#define TARGET_K "target"
#define SOLUTION_K "solution"

#define REQUIRE_DRAMATICALLY(condition, message) { \
if (!(condition)) { \
std::cout << "Error: " << message << std::endl; \
abort(); \
} \
}

/** @brief executes a POST query with curl passing body as json returns the json answer */
json11::Json post_query(const std::string& url, const json11::Json& body) {
    std::string curl = "/usr/bin/curl";
    std::string data_raw = "--data-raw";
    std::string H = "-H";
    std::string sS = "-sS";
    std::string ContentTypeStr = "Content-Type: application/json";
    std::vector<char*> argv;
    std::string bodys = body.dump();
    std::string reps;
    argv.emplace_back((char*) curl.c_str());
    argv.emplace_back((char*) sS.c_str());
    argv.emplace_back((char*) H.c_str());
    argv.emplace_back((char*) ContentTypeStr.c_str());
    argv.emplace_back((char*) data_raw.c_str());
    argv.emplace_back((char*) bodys.c_str());
    argv.emplace_back((char*) url.c_str());
    argv.emplace_back((char*) nullptr);
    std::cout << "running: " << curl << " ";
    for (char* arg : argv) if (arg) std::cout << arg << " ";
    std::cout << std::endl;
    int from_curl[2];
    int ret = pipe(from_curl);
    REQUIRE_DRAMATICALLY(ret==0, "pipe failed: " <<strerror(errno));
    if (fork()) {
        // father reads the pipe to the end
        char c;
        close(from_curl[1]);
        while (true) {
            int ret = read(from_curl[0], &c, 1);
            REQUIRE_DRAMATICALLY(ret>=0, "error reading from curl");
            if (ret==0) break;
            if (ret==1) reps.push_back(c);
        }
        std::string err;
        json11::Json r =  json11::Json::parse(reps, err);
        REQUIRE_DRAMATICALLY(err.empty(), "not a json: " << err << std::endl << reps);
        return r;
    } else {
        // child executes curl and stdout to the pipe
        close(from_curl[0]);
        dup2(from_curl[1], 1);
        close(from_curl[1]);
        //close(2);
        close(0);
        execv(curl.c_str(), argv.data());
    }
    REQUIRE_DRAMATICALLY(false, "unreachable code");
}

/** @brief base64 decoding */
std::vector<uint8_t> base64_decode(const std::string& b64) {
    size_t olen;
    mbedtls_base64_decode(nullptr, 0, &olen, (uint8_t*) b64.data(), b64.size());
    std::vector<uint8_t> reps(olen);
    mbedtls_base64_decode(reps.data(), olen, &olen, (uint8_t*) b64.data(), b64.size());
    reps.resize(olen);
    return reps;
}

/** @brief base64 encoding */
std::string base64_encode(const std::vector<uint8_t>& binary) {
    size_t olen;
    mbedtls_base64_encode(nullptr, 0, &olen, binary.data(), binary.size());
    std::string reps(olen, '\0');
    mbedtls_base64_encode((uint8_t*) reps.data(), olen, &olen, binary.data(), binary.size());
    reps.resize(olen);
    return reps;
}

/** @brief randomizes data */
void randomize(std::vector<uint8_t>& data) {
    FILE* F = fopen("/dev/urandom", "rb");
    REQUIRE_DRAMATICALLY(fread(data.data(), data.size(), 1, F)==1, "error reading /dev/urandom");
    fclose(F);
}

/** @brief increment data (little endian) */
void increment(std::vector<uint8_t>& data) {
    for (uint64_t i=0; i<data.size(); ++i) {
        if (++data[i]) break;
    }
}

/** @brief sha256 of the concatenation of salt and data */
void hash(std::vector<uint8_t>& dest, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& data) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, false);
    mbedtls_sha256_update_ret(&ctx, salt.data(), salt.size());
    mbedtls_sha256_update_ret(&ctx, data.data(), data.size());
    mbedtls_sha256_finish_ret(&ctx, dest.data());
    mbedtls_sha256_free(&ctx);
}


int main() {
    std::string worker_id;

    // Obtain the worker id
    std::cout << "Obtaining worker id..." << std::endl;
    json11::Json wid = post_query(BASE_URL "/api/register", json11::Json::object{});
    REQUIRE_DRAMATICALLY(wid.is_string(), "received worker id is not a string");
    worker_id = wid.string_value();
    REQUIRE_DRAMATICALLY(!worker_id.empty(), "worker id is empty");


    // Start of the main loop
    std::vector<uint8_t> message(16);
    std::vector<uint8_t> hashcode(32);
    int64_t challenge_id = -1;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> target;
    while (true) {
        // Retrieve the next challenge
        std::cout << "Retrieving the next challenge..." << std::endl;
        json11::Json challenge = post_query(BASE_URL "/api/get-challenge", json11::Json::object{
                {WORKER_ID_K, worker_id},
                {CHALLENGE_ID_K, double(challenge_id)}
        });
        REQUIRE_DRAMATICALLY(
                challenge.is_object() && challenge[CHALLENGE_ID_K].is_number(),
                "challenge is invalid");
        challenge_id = challenge[CHALLENGE_ID_K].int_value();
        if (challenge_id == -1) exit(0);
        salt = base64_decode(challenge[SALT_K].string_value());
        target = base64_decode(challenge[TARGET_K].string_value());
        std::cout << "challenge " << challenge_id << std::endl;
        std::cout << "salt: " << base64_encode(salt) << std::endl;
        std::cout << "target: " << base64_encode(target) << std::endl;
        // try to crack the challenge for 1 minute
        std::chrono::time_point deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        randomize(message);
        while (std::chrono::steady_clock::now() < deadline) {
            hash(hashcode, salt, message);
            if (memcmp(hashcode.data(), target.data(), target.size())==0) {
                // victory!!! we found a solution
                post_query(BASE_URL "/api/submit-solution", json11::Json::object{
                        {WORKER_ID_K, worker_id},
                        {CHALLENGE_ID_K, double(challenge_id)},
                        {SOLUTION_K, base64_encode(message)}
                });
                break;
            }
            increment(message);
        }
    }
    return 0;
}
