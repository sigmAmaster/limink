#pragma once
#include <cryptopp/config_int.h>
#include <cryptopp/secblock.h>
#include <cryptopp/words.h>

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
 * */

void passwdGate(CryptoPP::SecByteBlock *buff);
