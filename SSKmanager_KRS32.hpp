#pragma once
#include <cryptopp/allocate.h>
#include <cryptopp/config_int.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/sha3.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sys/types.h>

/*
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
 * key manager with
 * sha3 * sha3 hash and KRS 32
 *
 * sutible for aes256  and
 * other alghorithm with 32 byte key size
 *
 * */

//  key row size
#define KRS 32

/// create chain of keys for N100 alghorithm
class SSK32 {

public:
  explicit SSK32(CryptoPP::SecByteBlock &KingKey)
      : columnChain(64), Column(), Row() {

    Column.Update(KingKey, KingKey.size());

    Column.Final(columnChain);

    Column.Restart();

    internalCounter = 1;
    KingKey.CleanNew(1);
  };

  ~SSK32() {

    columnChain.CleanNew(1);

    Column.Restart();

    Row.Restart();
  };

  void Krow(CryptoPP::SecByteBlock &buff);

private:
  void kmake();

  CryptoPP::SecByteBlock columnChain;

  std::uint16_t internalCounter;

  CryptoPP::SHA3_512 Column;
  CryptoPP::SHA3_384 Row;
};
