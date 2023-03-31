#include "BShifter.hpp"
#include <algorithm>
#include <cryptopp/config_int.h>
#include <cryptopp/secblock.h>
#include <cryptopp/secblockfwd.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <system_error>static 

static string msg;

using namespace CryptoPP;
using namespace std;

void BShifter::lock() {

  auto Shifter = [this](size_t loop) {
    SecByteBlock tmp(1);
   
    for (size_t c1 = 0, c2 = (this->size() - 1); c1 < loop; c2--, c1++) {

      try {

        tmp[0] = this[0][c1];

        *(this->BytePtr() + c1) = this[0][c2];
        *(this->BytePtr() + c2) = tmp[0];

      } catch (exception &e) {

        throw e.what();
        break;
      };
    }
  };

  try {

    if (Loop >= (this->size() / 2)) {

      try {
        reverse(this->begin(), this->end());
      } catch (exception &e) {
        throw e.what();
      };

      Shifter((Loop - (this->size() / 2)));

    }

    else
      Shifter(Loop);

  } catch (const char *massage) {

    msg= "ID B2 what:\n  ";
    msg += massage;

    throw msg.c_str();
  };

  if (!locked)
    locked = true;
  else
    locked = false;
};

void BShifter::operator=(SecByteBlock &data) {
  if (data.size() <= this->size()) {
    internalCounter += data.size();
    this->Assign(data, data.size());
  }

  else
    throw "ID B3\n";
};

void BShifter::operator=(BShifter &data) {

  if (data.size() <= this->size()) {
    internalCounter += data.size();

    for (size_t s = 0; s < data.size(); s++)
      *(this[0].BytePtr() + s) = *(data.BytePtr() + s);

  } else
    throw "ID B4\n";
};

void BShifter::operator=(std::string &data) {

  if (sizeof(data) <= this->size()) {
    internalCounter += data.size();

    for (size_t s = 0; s < data.size(); s++)
      *(this[0].BytePtr() + s) = static_cast<CryptoPP::byte>(data[s]);

  } else
    throw "ID B8\n";
}

void BShifter::operator+=(CryptoPP::byte BYTE) {

  if (internalCounter <= this->size()) {

    *(this->BytePtr() + internalCounter) = BYTE;
    internalCounter++;

  }

  else
    throw "ID B5";
};


void BShifter::operator+=(std::string &data) {

  if (sizeof(data) <= this->size()) {
    internalCounter += data.size();

    for (size_t s = 0; s < data.size(); s++)
      *(this[0].BytePtr() + s) = static_cast<CryptoPP::byte>(data[s]);

  } else
    throw "ID B9\n";
};

const size_t BShifter::free_mem() const {

  if (internalCounter < this->size())
    return this->size() - internalCounter;

  else
    return 0;
};
