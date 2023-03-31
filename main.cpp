#include "Package.hpp"
#include "Pverf.hpp"
#include <cryptopp/secblockfwd.h>
#include <cryptopp/sha3.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

void help() {

  std::cout << "\nwelcome to limink help menu: \n";
  std::cout << "-e : encrypt file \n";
  std::cout << "-d : decrypt package \n";
  std::cout << "-o : output file or destion  \n";
  std::cout << "-h : print help menu\n";

  std::cout << "encryption methods: \n";
  std::cout << "--aes : default \n";
  std::cout << "--rc6 \n";
  std::cout << "--mars \n";
  std::cout << "--twofish \n";
  std::cout << "--serpent\n";
  std::cout << "--aria \n";

  std::cout << "\n--worker : number of thread(2 is default)\n";

  std::cout << "\nencryption example : \n"
            << "./limink --rc6 --worker 4 -e movie.mp4 music.mp3 ~/Pictures/ "
               "-o MyPackage\n";

  std::cout << "\ndecryption example : \n"
            << "./limink --rc6 --worker 8 -d MyPackage -o ~/Folder/ \n";

  std::cout << "\nDevelop By sigmAmster Σ \n";
  exit(EXIT_SUCCESS);
}

using namespace CryptoPP;

static const char *DefualtName = "LimInk";
static const char *DefualtExtarct = "./";

int main(const int argc, char **argv) {

  bool options[3] = {false};

  const char *encMethod = "--aes";

  uint8_t thn = 2;

  std::vector<std::string> fileList;

  auto UnknowArg = []() {
    std::cout << "\nERR, unknow arguments !!!.\nenter -h to print help\n";
    exit(EXIT_FAILURE);
  };

  try {

    if (argc > 1 && !strcmp(argv[1], "-h"))
      help();

    if (argc < 3)
      UnknowArg();

    for (size_t v = 1; v < argc; v++) {

      if (!std::strcmp(argv[v], "--aes"))
        encMethod = argv[v];

      else if (!std::strcmp(argv[v], "--rc6"))
        encMethod = argv[v];

      else if (!std::strcmp(argv[v], "--mars"))
        encMethod = argv[v];

      else if (!std::strcmp(argv[v], "--serpent"))
        encMethod = argv[v];

      else if (!std::strcmp(argv[v], "--twofish"))
        encMethod = argv[v];

      else if (!std::strcmp(argv[v], "--aria"))
        encMethod = argv[v];

      else if (!strcmp(argv[v], "--worker")) {

        v++;

        if (std::isdigit(argv[v][0])) {

          size_t threadNum = 0;

          std::stringstream ss;

          ss << argv[v];
          ss >> threadNum;
          ss.clear();

          if (threadNum > 255)
            throw "\nERR, maximum thread is 255 !!!\n";
          else
            thn = threadNum;
        }

        else
          throw "\nERR, invalid argument for thread number \n";

      }

      else if (!strcmp(argv[v], "-e"))
        options[2] = true;

      else if (!strcmp(argv[v], "-d"))
        options[1] = true;

      else if (!strcmp(argv[v], "-o"))
        options[0] = true;

      else if (!strcmp(argv[v], "-h"))
        help();

      else
        fileList.push_back(argv[v]);
    }

    if (options[1] && options[2])
      throw "\nERR, you cant select multi options !!!\n";

    if (!options[1] && !options[2])
      throw "\nERR, you need select encryption or decryption !!!\n";

    // if user not define extract path or archive name
    // use defualt name and path
    if (!options[0] && options[2])
      fileList.push_back(DefualtName);

    if (!options[0] && options[1])
      fileList.push_back(DefualtExtarct);

    SecByteBlock passwd(64);
    passwdGate(&passwd);

    // Package constructor do all work after calling

    Package *pack = new Package(fileList, encMethod, passwd, options[2], thn);

    std::cout << "\nTotal Time: " << pack->Time() / 1000000 << std::endl;
    // delete object
    delete pack;
    std::cout << "\n DONE \n";

  } catch (const char *msg) {
    std::cout << msg << '\n';
  }
}
