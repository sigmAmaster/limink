#include "SSKmanager_KRS32.hpp"
#include <cryptopp/secblockfwd.h>
#include <cstdint>
#include <iostream>

using namespace CryptoPP;

void SSK32::Krow(SecByteBlock &buff) {

  if (internalCounter == 1 || internalCounter == 2) {

    buff.CleanNew(48);

    Row.Update((columnChain.BytePtr() + (KRS * (internalCounter - 1))), 32);

    Row.Final(buff);

    Row.Restart();


  }

  else {
    kmake();
    buff.CleanNew(48);

    Row.Update((columnChain.BytePtr() + (KRS * (internalCounter - 1))), 32);

    Row.Final(buff.BytePtr());

    Row.Restart();

  }

  internalCounter++;
}

void SSK32::kmake() {

  internalCounter = 1;

  Column.Restart();

  Column.Update(columnChain, columnChain.size());

  Column.Final(columnChain);

  return;
}
