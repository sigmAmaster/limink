#include "files.hpp"

namespace fs = std::filesystem;

IFiles::IFiles(const char *name, std::uint64_t Id) : ID(Id) {

  // read file

  try {

    if (!fs::exists(name)) {
      err = "ERR, File ";
      err += name;
      err += " Doesnt Exsist !!!\n";
      throw err.c_str();
    } else {

      fileSize = fs::file_size(name);
      Fin = new std::ifstream();

      Fin->open(name, std::ios::binary | std::ios::app);

      // Fin->seekg(std::ios::end);

      std::string FileSize(" SIZE: ");

      FileSize += std::to_string(fileSize);

      fs::file_time_type ftt = fs::last_write_time(name);

      std::time_t tt = to_time_t(ftt);
      std::tm *gmt = std::gmtime(&tt);

      std::stringstream ss;
      ss << std::put_time(gmt, "%A, %d %B %Y %H:%M");

      std::string LastEdit(" MODI: ");
      LastEdit += ss.str();

      filter_name(name);

      std::string id(" ID: ");
      id += std::to_string(ID);

      std::string headStr("NAME: ");

      headStr += Name;
      headStr += FileSize;
      headStr += id;
      headStr += LastEdit;

      if (headStr.size() > HBS)
        throw "ERR, ID F3 \n";
      Header = std::make_shared<BShifter>(HBS, 0);

      *Header = headStr;
      Remain = fileSize;
    }

  } catch (const char *msg) {

    throw msg;
  }
};

const size_t IFiles::size() const { return fileSize; };
const size_t IFiles::how_much_read() const { return Remain; };
const char *IFiles::get_name() const { return Name.c_str(); };
const uint64_t IFiles::get_id() const { return ID; };

const std::shared_ptr<BShifter> IFiles::header() const { return Header; };

void IFiles::filter_name(const char *n) {
  std::stringstream ss;
  std::string line;
  std::vector<std::string> Data;

  ss << n;

  while (getline(ss, line, '/')) {
    Data.push_back(line);
    line.clear();
  }

  for (char &y : Data.back())
    if (y == ' ')
      y = '-';

  Name = Data.back();
};

void IFiles::read(BShifter *Buffer) {
  try {
    Remain -= Buffer->size();

    Fin->read(reinterpret_cast<char *>(Buffer->BytePtr()), Buffer->size());

  } catch (const char *msg) {
    throw msg;
  }
};

IFiles::~IFiles() {
  try {

    Fin->clear();
    Fin->close();
    delete Fin;

  } catch (const char *e) {
    throw e;
  }
};
