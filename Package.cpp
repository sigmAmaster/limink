
#include "Package.hpp"
#include <ios>
namespace FS = std::filesystem;

Package::Package(std::vector<std::string> &fileList, const char *encMethod,
                 CryptoPP::SecByteBlock &MainKey, bool options,
                 const uint8_t thread)
    : Pack(new std::fstream()), THPS(thread) {

  keyManager = new SSK32(MainKey);

  try {
    Comp = 0;
    TotalTime = 0;

    init__operation(encMethod);

    // process options
    // if encrypt file
    if (options) {

      // save package name;
      this->Name = fileList.back().c_str();
      fileList.pop_back();

      int64_t id = -1;
      std::vector<std::string> Files;
      std::vector<std::string> SearchRes;

      for (auto itr = fileList.begin(); itr != fileList.end(); itr++) {

        /// auto detect directory
        /// list all file in directory
        if (FS::is_directory(*itr)) {

          SearchRes = dir_search(fileList);

          for (auto &FileNames : SearchRes) {

            Files.push_back(FileNames);
            id++;
          }
        }

        else {

          Files.push_back(*itr);
          id++;
        }
      }

      for (auto &FileNames : Files) {

        Fin.push_back(std::make_unique<IFiles>(FileNames.c_str(), id));
        SIZE += Fin.back()->size() + HBS;
        id--;
      }

      // create hiden temporary file to process
      std::string Fname(".");

      Fname += Name;
      Fname += ".tmp";

      // make temp file
      Pack->open(Fname, std::fstream::in | std::fstream::out |
                            std::fstream::binary | std::fstream::trunc);

      // check package is open
      if (!Pack->is_open())
        throw Pack->exceptions();

      // change permissions
      FS::permissions(Fname,
                      FS::perms::owner_all | FS::perms::none | FS::perms::none,
                      FS::perm_options::replace);

      // go to encryption
      lock();

    }
    // decrypt package

    else {

      if (!FS::is_directory(fileList.back()) && FS::exists(fileList.back()))
        throw "\nERR, Extract path is invalid !!!\n";

      this->ExtractPath = fileList.back().c_str();
      fileList.pop_back();

      ;

      std::vector<std::string> Files;

      for (const auto &PackName : fileList) {

        /// auto detect directory
        /// list all file in directory
        if (FS::is_directory(PackName))
          throw "\nERR, Decryption Directory is not valid !!!\n";

        else {
          SIZE = FS::file_size(PackName);
          unlock(PackName.c_str());
        }
      }
    }

  } catch (const char *msg) {

    std::cout << msg << std::endl;

    exit(EXIT_FAILURE);
  }
}

std::vector<std::string> Package::dir_search(std::vector<std::string> dirList) {

  std::vector<std::string> ListOfFile;

  std::cout << "Scanning directories.....\n";

  try {

    for (auto Litr : dirList) {

      if (!FS::is_directory(Litr)) {

        std::cout << "Encrypt File: " << Litr << std::endl;
        ListOfFile.push_back(Litr);

      }

      else
        for (auto &itr : FS::recursive_directory_iterator(Litr))
          if (!itr.is_directory()) {

            std::cout << "Encrypt File: " << itr.path().string() << std::endl;
            ListOfFile.push_back(itr.path().string());
          }
    }

  } catch (const char *msg) {
    throw msg;
  }

  return ListOfFile;
}
///

void Package::init_key() {
  CryptoPP::SecByteBlock mainK(48);
  // call sskm for create new key
  keyManager->Krow(mainK);

  KeyRow = new CryptoPP::SecByteBlock(32);
  Iv = new CryptoPP::SecByteBlock(16);

  KeyRow->Assign(mainK, 32);

  for (uint8_t q = 0, p = 32; q < 16 && p < 48; q++, p++)
    *(Iv->BytePtr() + q) = *(mainK.BytePtr() + p);

  CryptoPP::SHA3_256 loopMaker;
  CryptoPP::SecByteBlock loopBuff(32);

  loopMaker.Update(*Iv, Iv->size());
  loopMaker.Final(loopBuff.BytePtr());

  loop = new uint64_t;
  *loop = 0;

  for (uint64_t v = 0; v < (BS / 256); v++)
    *loop += *(loopBuff.BytePtr() + v);
}

void Package::THinit_key(uint8_t ThNum) {
  CryptoPP::SecByteBlock mainK(48);
  // call sskm for create new key
  keyManager->Krow(mainK);

  THKeyRow[ThNum]->Assign(mainK, 32);

  for (uint8_t q = 0, p = 32; q < 16 && p < 48; q++, p++)
    *(THIv[ThNum]->BytePtr() + q) = *(mainK.BytePtr() + p);

  CryptoPP::SHA3_256 loopMaker;
  CryptoPP::SecByteBlock loopBuff(32);

  loopMaker.Update(*THIv[ThNum], THIv[ThNum]->size());
  loopMaker.Final(loopBuff.BytePtr());

  *THloop[ThNum] = 0;

  for (uint64_t v = 0; v < (BS / 256); v++)
    *THloop[ThNum] += *(loopBuff.BytePtr() + v);
}

///
void Package::init__operation(const char *method) {

  if (!std::strcmp("--aes", method))
    crypt_method = &aes_xts;

  else if (!std::strcmp("--rc6", method))
    crypt_method = &rc6_xts;

  else if (!std::strcmp("--twofish", method))
    crypt_method = &twofish_xts;

  else if (!std::strcmp("--mars", method))
    crypt_method = &mars_xts;

  else if (!std::strcmp("--serpent", method))
    crypt_method = &serpent_xts;

  else if (!std::strcmp("--aria", method))
    crypt_method = &aria_xts;

  else
    throw "\nERR, Wrong Encryption Method!!!\n";

  // init thread worker
  threadPool = new std::future<void>[THPS];

  THBuff = new BShifter *[THPS];
  THBuffExp = new BShifter *[THPS];

  THKeyRow = new CryptoPP::SecByteBlock *[THPS];
  THIv = new CryptoPP::SecByteBlock *[THPS];
  THloop = new uint64_t *[THPS];

  for (uint8_t p = 0; p < THPS; p++) {

    THBuffExp[p] = new BShifter(BS, 0);
    THBuff[p] = new BShifter(BS, 0);
    THKeyRow[p] = new CryptoPP::SecByteBlock(32);
    THIv[p] = new CryptoPP::SecByteBlock(16);
    THloop[p] = new uint64_t;
  }

  // init mac
  init_key();

  Mac.SetKey(KeyRow->BytePtr(), KeyRow->size());

  MacKey = std::move(KeyRow);
  MacIv = std::move(Iv);
  MacLoop = new Struct64;

  MacLoop->Lnum = *loop;
  delete loop;
}

void Package::lock() {

  auto encryptOneBuff = [&](BShifter *buff) {
    init_key();

    size_t *Lp = new size_t;
    *Lp = 0;

    // copy buffer to pervent
    // auto delete from encryption methods
    //
    Buff = new BShifter(buff->size(), 0);

    crypt_method(buff, KeyRow, Buff, Iv, Lp, true);

    delete KeyRow;
    delete Iv;
    delete Lp;
  };

  bool eof = false;

  // read all file form file list
  for (auto Fcounter = Fin.begin(); Fcounter != Fin.end(); Fcounter++) {

    auto itr = Fcounter->get();

    // encrypt header
    encryptOneBuff(itr->header().get());

    Pack->write(reinterpret_cast<const char *>(Buff->BytePtr()), Buff->size());
    delete Buff;

    // count possible working thread
    uint8_t operationCounter = 0;

    eof = true;
    while (eof) {

      // set time on start process
      Sproc = time_now();

      // create thread per buffer, each thread
      // encrypt buffer and return result
      for (uint8_t t = 0; t < THPS; t++) {

        // read file untile last buffer
        if (itr->how_much_read() > BS) {

          THinit_key(t);
          itr->read(THBuff[t]);

          // lunch thread and linked to pool
          threadPool[t] =
              std::async(std::launch::async, *crypt_method, THBuff[t],
                         THKeyRow[t], THBuffExp[t], THIv[t], THloop[t], true);

          // create thread was seccuseful
          operationCounter++;

          // break loop and go to other file
        } else {

          // write remain data

          eof = false;
          break;
        }
      }

      for (uint8_t t = 0; t < operationCounter; t++)
        // callback thread to get result
        threadPool[t].get();

      for (uint8_t t = 0; t < operationCounter; t++) {

        // compelete data processing
        Comp += BS;

        // write buffers to Package
        Pack->write(reinterpret_cast<char *>(THBuffExp[t]->data()),
                    THBuffExp[t]->size());

        // clear thread pool
      }

      // show progress status
      status();
      operationCounter = 0;
    }

    if (itr->how_much_read() != 0) {

      size_t r = itr->how_much_read();
      Comp += r;

      init_key();

      size_t *Lp = new size_t(0);

      Buff = new BShifter(r, 0);
      itr->read(Buff);

      crypt_method(Buff, KeyRow, THBuffExp[0], Iv, Lp, true);

      delete Buff;
      delete KeyRow;
      delete Iv;
      delete Lp;

      Pack->write(reinterpret_cast<const char *>(THBuffExp[0]->data()), r);
    }
  }

  create_mac();
};

////

const char *Package::name() const { return Name; }
const size_t Package::Time() const { return TotalTime; };

////

void Package::create_mac() {

  BShifter *MacBuff;

  std::ofstream Export;

  std::string finalFile(Name);
  finalFile += ".lipack";

  // create random size for mac buffer
  // random buffer size can perevent to
  // detect file size (in theory)
  // we use loop value
  size_t Bs = 0;

  do {

    for (size_t u = 0; u < 8; u++)
      Bs += *(MacLoop->Lchar + u);

    MacBuff = new BShifter(Bs, 0);

    // random buffer size must be bigger than 64
    if (Bs > 64)
      break;

    else
      delete MacBuff;

  } while (true);

  // fill rand data
  rnd.GenerateBlock(MacBuff->BytePtr(), MacBuff->size());

  char Buffer[BS] = {'\0'};

  Pack->seekg(Pack->beg);
  Pack->clear();
  Pack->flush();

  if (Pack->bad())
    throw Pack->exceptions();

  Export.open(finalFile, std::ios::binary | std::ios::trunc);

  if (!Export.is_open())
    throw "ERR, ID P5\n";

  // calcualte hash
  while (*Pack) {

    Pack->read(Buffer, BS);
    Export.write(Buffer, Pack->gcount());
    Mac.Update(reinterpret_cast<CryptoPP::byte *>(Buffer), Pack->gcount());
  }

  Mac.Final(*MacBuff);

  size_t *LOOP = new size_t;
  *LOOP = 0;

  // write mac on first of file
  Export.write(reinterpret_cast<char *>(MacBuff->BytePtr()), MacBuff->size());

  Export.flush();
  Export.close();

  Pack->flush();
  Pack->close();

  finalFile.clear();
  finalFile = '.';
  finalFile += Name;
  finalFile += ".tmp";
  FS::remove(finalFile);
}
////////////

void Package::verify_mac(BShifter *FileMac) {

  CryptoPP::SecByteBlock MacBuff(64);

  Mac.Final(MacBuff.BytePtr());

  Mac.Restart();

  for (uint8_t i = 0; i < 64; i++)
    if (*(MacBuff.BytePtr() + i) != *(FileMac->BytePtr() + i))
      throw "ERR,Maybe Password is Wrong or File has Been Change !!!\n";
  Pack->clear();
}

///////////
void Package::status() {

  // calculate percentage
  float Percent = ((float)(Comp) / SIZE) * 100;

  // set time on end of preocess
  auto Eproc = time_now();

  // total time untile now
  TotalTime += duration_cast<std::chrono::nanoseconds>(Eproc - Sproc).count();

  // clear line
  printf("%c", '\r');

  // remain time to finish entire process
  size_t remainT = (TotalTime / Comp) * (SIZE - Comp);

  // print time information
  std::cout << "Rtime(ms): " << remainT / 1000000 << '\t';

  // print percentage bar
  for (uint8_t l = 0; l < uint8_t(Percent); l++)
    printf("%c", '|');

  for (uint8_t l = 0; l < uint8_t(100 - Percent); l++)
    printf("%c", ' ');

  // print percentage number
  std::cout << std::setprecision(3) << Percent;
  std::cout << std::fixed;
  return;
}

void Package::unlock(const char *PackName) {

  std::cout << "\nDecrypt Package " << PackName << std::endl;

  try {

    Pack->open(PackName, std::ios::in | std::ios::binary);

    // check package is open
    if (!Pack->is_open())
      throw "\nERR, Can't open package !!!\n";

    auto uncryptOneBuff = [&](BShifter *buff) {
      init_key();

      size_t *Lp = new size_t;
      *Lp = 0;

      Buff = new BShifter(buff->size(), 0);

      crypt_method(buff, KeyRow, Buff, Iv, Lp, false);

      delete KeyRow;
      delete Iv;
      delete Lp;
    };

    // read mac
    BShifter *MacBuff;
    char TmpBuffer[BS] = {'\0'};
    size_t Bs = 0;

    do {

      for (size_t u = 0; u < 8; u++)
        Bs += *(MacLoop->Lchar + u);

      MacBuff = new BShifter(Bs, 0);

      // random buffer size must be bigger than 64
      if (Bs > 64)
        break;

      else
        delete MacBuff;

    } while (true);

    Pack->seekg((SIZE - MacBuff->size()));

    size_t pos = Pack->tellg();

    Pack->read(reinterpret_cast<char *>(MacBuff->BytePtr()), MacBuff->size());
    Pack->seekg(std::fstream::beg);

    // calcualte hmac for file
    while (Pack->tellg() < pos) {

      if ((pos - Pack->tellg()) > BS)
        Pack->read(reinterpret_cast<char *>(TmpBuffer), BS);
      else
        Pack->read(reinterpret_cast<char *>(TmpBuffer), pos - Pack->tellg());
      Mac.Update((CryptoPP::byte *)TmpBuffer, Pack->gcount());
    }

    verify_mac(MacBuff);

    delete MacBuff;

    Pack->seekg(std::fstream::beg);
    Pack->clear();
    Pack->flush();

    uint64_t FileId = 100;

    // header buffer
    BShifter encryptedHeader(HBS, 0);

    do {
      // read header
      Pack->read(reinterpret_cast<char *>(encryptedHeader.BytePtr()),
                 encryptedHeader.size());

      // unlock header file
      uncryptOneBuff(&encryptedHeader);

      std::string text1, text2, text3, text4, name, last, size;

      // read header
      ss << Buff->BytePtr();
      ss >> text1 >> name >> text2 >> size >> text4 >> FileId >> text3;

      // read last edit beause of space between character
      // we need read it char by char
      while (ss)
        last.push_back(ss.get());

      ss.flush();
      ss.clear();
      delete Buff;

      // verfy header
      // any dismatch means file is broken

      if (text1 != "NAME:")
        throw "ERR, ID P4-1\n";

      if (text2 != "SIZE:")
        throw "ERR, ID P4-2\n";

      if (text3 != "MODI:")
        throw "ERR, ID P4-3\n";

      if (text4 != "ID:")
        throw "ERR, ID P4-4\n";

      OFiles *Fout =
          new OFiles((ExtractPath + name).c_str(), size.c_str(), last.c_str());

      uint8_t operationCounter = 0;

      bool eof = true;
      while (eof) {

        // start timer
        Sproc = time_now();

        // create thread per buffer
        for (uint8_t t = 0; t < THPS; t++) {

          // read untile last buffer
          if (Fout->how_much_write() > BS) {

            THinit_key(t);

            Pack->read(reinterpret_cast<char *>(THBuff[t]->BytePtr()),
                       THBuff[t]->size());

            threadPool[t] = std::async(std::launch::async, *crypt_method,
                                       THBuff[t], THKeyRow[t], THBuffExp[t],
                                       THIv[t], THloop[t], false);
            *Fout += BS;

            operationCounter++;

          } else {

            eof = false;
            break;
          }
        }

        for (uint8_t t = 0; t < operationCounter; t++)
          threadPool[t].get();

        for (uint8_t t = 0; t < operationCounter; t++) {
          Comp += BS;
          Fout->write(THBuffExp[t]);
        }

        operationCounter = 0;
        status();
      }

      if (Fout->how_much_write() != 0) {

        init_key();
        size_t r = Fout->how_much_write();

        Buff = new BShifter(r, 0);
        BShifter *buff = new BShifter(r, 0);

        Pack->read(reinterpret_cast<char *>(Buff->BytePtr()), Buff->size());
        size_t *Lp = new size_t(0);

        crypt_method(Buff, KeyRow, buff, Iv, Lp, false);

        delete Buff;
        delete KeyRow;
        delete Iv;
        delete Lp;

        Fout->write(buff);
        delete buff;
      }

      delete Fout;
    } while (FileId != 0);

    Pack->clear();
    Pack->close();
  } catch (const char *msg) {

    throw msg;
  }
};
