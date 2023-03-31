#include "debuger.hpp"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include <chrono>
#include <cryptopp/config_int.h>
#include <cryptopp/crc.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/sha3.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <ostream>
#include <ratio>
#include <sys/types.h>
#include <thread>

void printHexValue(const char *name, const CryptoPP::SecByteBlock *const data,
                   size_t s) {

  std::cout << name << ":\n";

  CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));

  std::cout << s << std::endl;

  encoder.Put(data->BytePtr(), s);
  encoder.MessageEnd();

  std::cout << std::endl;
}

void printHexValue(const char *name, const CryptoPP::byte *const data,
                   size_t s) {

  std::cout << name << ":\n";

  CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));

  std::cout << "Size " << s << std::endl;

  encoder.Put(data, s);
  encoder.MessageEnd();

  std::cout << std::endl;
}

using namespace std::chrono;

uint64_t process_time(steady_clock::time_point &begin,
                      steady_clock::time_point &end, char accur) {

  uint64_t result;

  switch (accur) {

  case 'n':
    result = duration_cast<nanoseconds>(end - begin).count();
    break;

  case 'm':
    result = duration_cast<microseconds>(end - begin).count();
    break;

  case 'l':
    result = duration_cast<milliseconds>(end - begin).count();
    break;

  case 's':
    result = duration_cast<seconds>(end - begin).count();
    break;

  default:
    std::cout << "ERR, invalid argument for time process function !!!\n";
    exit(EXIT_FAILURE);
  }

  return result;
};
