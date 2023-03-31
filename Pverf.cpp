// #in
#include <cryptopp/secblockfwd.h>
#include <cryptopp/sha3.h>
#include <cstdint>
#include <iostream>

using namespace CryptoPP;

void passwdGate(SecByteBlock *buff) {

  SecBlock<byte, AllocatorWithCleanup<byte, true>> Tmp(1);
  SecByteBlock Schar(1);

  SecByteBlock holder1(64);

  SecByteBlock holder2(64);

  SHA3_512 Hash;

  printf("%s", "\nNOTES:Minimum Size 8 Word\n");
  printf("%s", "\n**************************************************\n");
  printf("%s", "Enter Your Password: \n");

  std::uint32_t count = 0;

  while (std::cin.read(reinterpret_cast<char *>(Schar.data()), Schar.size())) {

    if (Schar[0] == '\n')
      break;

    else {
      Tmp.CleanGrow(1);
      Tmp.Append(Schar, Schar.size());
      count++;
    }
  }

  if (Tmp.size() - 1 < 8) {

    printf("%s", "\n ERR, Your Password is too Short !!!\t ");
    printf("%li", Tmp.size() - 1);
    printf("%c", '\n');

    Schar.CleanNew(1);
    Tmp.CleanNew(1);

    exit(EXIT_FAILURE);
  }

  Hash.Update(Tmp.BytePtr(), Tmp.size() - 1);
  Hash.Final(holder1);
  Hash.Restart();

  count = 0;
  Tmp.CleanNew(1);
  printf("%s", "\nEnter Your Password Again: \n");

  while (std::cin.read(reinterpret_cast<char *>(Schar.data()), Schar.size())) {

    if (Schar[0] == '\n')
      break;

    else {
      Tmp.CleanGrow(1);
      Tmp.Append(Schar, Schar.size());
      count++;
    }
  }

  printf("%s", "\n**************************************************\n");
  Schar.CleanNew(1);

  Hash.Update(Tmp.BytePtr(), Tmp.size() - 1);
  Hash.Final(holder2);
  Hash.Restart();

  count = 0;
  Tmp.CleanNew(1);

  // check Password matches
  for (auto V1 = holder1.begin(), V2 = holder2.begin();
       V1 != holder1.end() && V2 != holder2.end(); V1++, V2++) {

    if (*V1 != *V2) {
      printf("%s", "ERR, Passwords Doesn't Match !!!\n");

      holder2.CleanNew(1);
      holder1.CleanNew(1);

      exit(EXIT_FAILURE);
    }
  }

  holder2.CleanNew(1);

  buff->Assign(holder1);

  holder1.CleanNew(1);
}
