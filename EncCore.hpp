#include "BShifter.hpp"
#include <cryptopp/secblockfwd.h>
#include <cryptopp/sha3.h>
#include <cstddef>
#include <memory>

/*

NOTE:
All XTS encryption need 256 bit key

#The GPLv3 License (GPLv3)

Copyright (c) 2023 sigmAmster

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

*/

extern void aes_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                    BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv, size_t *loop,
                    const bool mode);

extern void mars_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                     BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv,
                     size_t *loop, const bool mode);

extern void rc6_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                    BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv, size_t *loop,
                    const bool mode);

extern void twofish_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                        BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv,
                        size_t *loop, const bool mode);

extern void serpent_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                        BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv,
                        size_t *loop, const bool mode);

extern void aria_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key,
                     BShifter *EXPbuff, CryptoPP::SecByteBlock *Iv,
                     size_t *loop, const bool mode);
