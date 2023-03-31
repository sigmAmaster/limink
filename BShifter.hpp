#pragma once
#include <cryptopp/config_int.h>
#include <cryptopp/crc.h>
#include <cryptopp/secblock.h>
#include <cryptopp/secblockfwd.h>
#include <cstddef>
#include <cstdint>
#include <exception>
/*
 *
 *
 * The AGPLv3 License (AGPLv3)

 Copyright (c) 2023 sigmAmaster

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *
 * */
class BShifter : public CryptoPP::SecBlock<
                     CryptoPP::byte,
                     CryptoPP::AllocatorWithCleanup<CryptoPP::byte, true>> {

public:
  BShifter(const size_t size, const size_t loop)
      : CryptoPP::SecBlock<CryptoPP::byte, CryptoPP::AllocatorWithCleanup<
                                               CryptoPP::byte, true>>(size),
        locked(false), internalCounter(0) {
    try {
      Loop = loop;

      if (loop > size) {
        throw "ID B1";
      }

    }

    catch (const char *msg) {
      throw msg;
    }
  };

  ~BShifter() {

    // clean all  data
    for (auto d = this->begin(); d != this->end(); d++)
      *d = '\0';
  }

  void operator=(CryptoPP::SecByteBlock &);
  void operator=(BShifter &);

  void operator=(std::string &);

  void operator+=(std::string &);
  void operator+=(CryptoPP::byte);

  // void operator<<(CryptoPP::SecByteBlock &);

  // void operator>>(BShifter &);
  // void operator>>(CryptoPP::SecByteBlock &);

  CryptoPP::byte operator[](size_t);

  const bool is_locked() const { return locked; };

  const size_t free_mem() const;

  void lock();

  void inline changeLoop(size_t NewLoop) { Loop = NewLoop; };

private:
  bool locked;
  size_t internalCounter;
  size_t Loop;
};
