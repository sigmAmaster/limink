#include "EncCore.hpp"
#include "BShifter.hpp"
#include "cryptopp/aes.h"
#include "debuger.hpp"
#include <cryptopp/aria.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/mars.h>
#include <cryptopp/modes.h>
#include <cryptopp/rc6.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/serpent.h>
#include <cryptopp/twofish.h>
#include <cryptopp/xts.h>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <memory>

using namespace CryptoPP;

void aes_xts(BShifter *INPbuff, SecByteBlock *Key, BShifter *EXPbuff,
             SecByteBlock *Iv, size_t *loop, const bool mode) {

  if (mode) {

    try {

      EXPbuff->changeLoop(*loop);

      XTS_Mode<AES>::Encryption Encryption;
      Encryption.SetKeyWithIV(Key->BytePtr(), Key->size(), Iv->BytePtr());

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Encryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

      EXPbuff->lock();

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }

  else {

    try {
      INPbuff->changeLoop(*loop);

      INPbuff->lock();

      XTS_Mode<AES>::Decryption Decryption;
      Decryption.SetKeyWithIV(*Key, Key->size(), *Iv);

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Decryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }
}
///////////////
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
void twofish_xts(BShifter *INPbuff, SecByteBlock *Key, BShifter *EXPbuff,

                 SecByteBlock *Iv, size_t *loop, const bool mode) {

  if (mode) {

    try {
      EXPbuff->changeLoop(*loop);

      XTS_Mode<Twofish>::Encryption Encryption;
      Encryption.SetKeyWithIV(Key->BytePtr(), Key->size(), Iv->BytePtr());

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Encryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

      EXPbuff->lock();

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }

  else {

    try {

      INPbuff->changeLoop(*loop);
      INPbuff->lock();

      XTS_Mode<Twofish>::Decryption Decryption;
      Decryption.SetKeyWithIV(*Key, Key->size(), *Iv);

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Decryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }
}
//////////
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
void aria_xts(BShifter *INPbuff, SecByteBlock *Key, BShifter *EXPbuff,
              SecByteBlock *Iv, size_t *loop, const bool mode) {
  if (mode) {

    try {

      EXPbuff->changeLoop(*loop);

      XTS_Mode<ARIA>::Encryption Encryption;
      Encryption.SetKeyWithIV(Key->BytePtr(), Key->size(), Iv->BytePtr());

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Encryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

      EXPbuff->lock();

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }

  else {

    try {

      INPbuff->changeLoop(*loop);
      INPbuff->lock();

      XTS_Mode<ARIA>::Decryption Decryption;
      Decryption.SetKeyWithIV(*Key, Key->size(), *Iv);

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Decryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }
}
//////////
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///
///

void serpent_xts(BShifter *INPbuff, SecByteBlock *Key, BShifter *EXPbuff,
                 SecByteBlock *Iv, size_t *loop, const bool mode) {
  if (mode) {

    try {

      EXPbuff->changeLoop(*loop);

      XTS_Mode<Serpent>::Encryption Encryption;
      Encryption.SetKeyWithIV(Key->BytePtr(), Key->size(), Iv->BytePtr());

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Encryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

      EXPbuff->lock();

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }

  else {

    try {

      INPbuff->changeLoop(*loop);
      INPbuff->lock();

      XTS_Mode<Serpent>::Decryption Decryption;
      Decryption.SetKeyWithIV(*Key, Key->size(), *Iv);

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Decryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }
}
////
///
///
///
///
///
///
///
///
///
///
///
///
///
///

void rc6_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key, BShifter *EXPbuff,
             CryptoPP::SecByteBlock *Iv, size_t *loop, const bool mode) {
  if (mode) {

    try {

      EXPbuff->changeLoop(*loop);

      XTS_Mode<RC6>::Encryption Encryption;
      Encryption.SetKeyWithIV(Key->BytePtr(), Key->size(), Iv->BytePtr());

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Encryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

      EXPbuff->lock();
    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }

  else {

    try {

      INPbuff->changeLoop(*loop);
      INPbuff->lock();

      XTS_Mode<RC6>::Decryption Decryption;
      Decryption.SetKeyWithIV(*Key, Key->size(), *Iv);

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Decryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

    } catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }
}
/////////
///
///
///
///
///
///
///
///
///
///
////
///
///
void mars_xts(BShifter *INPbuff, CryptoPP::SecByteBlock *Key, BShifter *EXPbuff,
              CryptoPP::SecByteBlock *Iv, size_t *loop, const bool mode) {

  if (mode) {

    try {

      EXPbuff->changeLoop(*loop);

      XTS_Mode<MARS>::Encryption Encryption;
      Encryption.SetKeyWithIV(Key->BytePtr(), Key->size(), Iv->BytePtr());

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Encryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

      EXPbuff->lock();

    } catch (void *msg) {
      printf("%s", "ERR, Encryption has incompleted !!!\n");
      exit(EXIT_FAILURE);
    }
  }

  else {

    try {

      INPbuff->changeLoop(*loop);
      INPbuff->lock();

      XTS_Mode<MARS>::Decryption Decryption;
      Decryption.SetKeyWithIV(*Key, Key->size(), *Iv);

      ArraySource(
          INPbuff->BytePtr(), INPbuff->size(), true,
          new StreamTransformationFilter(
              Decryption, new ArraySink(EXPbuff->BytePtr(), EXPbuff->size())));

    } catch (Exception e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }

    catch (const char *e) {
      printf("%s",
             "ERR, Decryption has incompleted (maybe password is wrong) !!!\n");
      exit(EXIT_FAILURE);
    }
  }
}
