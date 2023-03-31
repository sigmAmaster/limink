#include "BShifter.hpp"
#include "EncCore.hpp"
#include "SSKmanager_KRS32.hpp"
#include "files.hpp"
#include <chrono>
#include <cryptopp/config_int.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>
#include <cryptopp/randpool.h>
#include <cryptopp/sha3.h>
#include <cstdint>
#include <exception>
#include <future>
#include <iomanip>
#include <random>
#include <string>
#include <vector>

/*
 *
 * #The GPLv3 License (GPLv3)

 Copyright (c) 2023 sigmAmaster

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */

// buffer size
#define BS 2048

union Struct64 {

  std::uint64_t Lnum;
  unsigned char Lchar[8];
};

class Package {

public:
  explicit Package(std::vector<std::string> &fileList, const char *encMethod,
                   CryptoPP::SecByteBlock &MainKey, bool options,
                   const uint8_t thread);

  ~Package() {

    delete keyManager;
    Pack.get_deleter();
    delete MacLoop;
    delete[] threadPool;

    for (uint8_t counter = 0; counter < THPS; counter++) {
      delete THBuff[counter];
      delete THIv[counter];
      delete THKeyRow[counter];
      delete THloop[counter];
      delete THBuffExp[counter];
    }

    delete[] THBuff;
    delete[] THIv;
    delete[] THKeyRow;
    delete[] THloop;
    delete[] THBuffExp;

    ss.clear();
    ss.flush();
    Mac.Restart();
  }
  const char *name() const;

  const size_t Time() const;

private:
  SSK32 *keyManager;

  void file_stream();

  void init__operation(const char *method);

  void (*crypt_method)(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                       BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv,
                       size_t *loop, const bool mode);

  std::vector<std::string> dir_search(std::vector<std::string>);

  void create_mac();
  void verify_mac(BShifter *);

  void init_key();
  void THinit_key(uint8_t);

  void status();
  void lock();
  void unlock(const char *);

  std::unique_ptr<std::fstream> Pack;

  BShifter *Buff;
  CryptoPP::SecByteBlock *KeyRow;
  CryptoPP::SecByteBlock *Iv;
  std::uint64_t *loop;

  std::vector<std::unique_ptr<IFiles>> Fin;

  std::future<void> *threadPool;

  inline std::chrono::steady_clock::time_point time_now() {
    return std::chrono::steady_clock::now();
  };

  const uint8_t THPS;
  BShifter **THBuff;
  BShifter **THBuffExp;
  CryptoPP::SecByteBlock **THKeyRow;
  CryptoPP::SecByteBlock **THIv;
  std::uint64_t **THloop;

  std::chrono::steady_clock::time_point Sproc;

  CryptoPP::RandomPool rnd;

  const char *Name;
  std::string ExtractPath;

  CryptoPP::HMAC<CryptoPP::SHA3_512> Mac;
  CryptoPP::SecByteBlock *MacKey, *MacIv;
  Struct64 *MacLoop;

  std::stringstream ss;

  std::size_t Comp;
  std::size_t SIZE;
  std::size_t TotalTime;
};
