#include "cryptopp/secblock.h"
#include <cstddef>
#include <iostream>

#define Debuge 1

#define Debuge2 0

extern void printHexValue(const char *name,
                          const CryptoPP::SecByteBlock *const data, size_t s);

extern void printHexValue(const char *name, const CryptoPP::byte *const data,
                          size_t s);

extern void KeyPossibility(uint64_t count, const uint64_t wth, bool timing,
                           CryptoPP::SecByteBlock *mainKey, uint64_t Test);

inline std::chrono::steady_clock::time_point start_timer() {
  return std::chrono::steady_clock::now();
};

inline std::chrono::steady_clock::time_point end_timer() {
  return std::chrono::steady_clock::now();
};

extern uint64_t process_time(std::chrono::steady_clock::time_point &begin,
                             std::chrono::steady_clock::time_point &end,
                             char accur);
