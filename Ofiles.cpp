#include "files.hpp"

OFiles::OFiles(const char *name, const char *size, const char *lastedit)
    : lastEdit(lastedit) {

  try {

    if (std::filesystem::exists(name)) {
      err = "ERR, Can't Extract ";

      err += name;
      err += " File Already Exists !!!";
      throw err.c_str();
    }

    else {
      Name = name;
      std::stringstream ss;

      ss << size;
      ss >> fileSize;
      ss.clear();
      Remain = 0;

      lastEdit = lastedit;

      Fout = new std::ofstream();
      Fout->open(name, std::ios::binary);
      Remain = fileSize;
    }
  } catch (const char *msg) {

    throw msg;
  }
};

const uint64_t OFiles::how_much_write() const { return Remain; };

void OFiles::operator+=(size_t S) {

  if (Remain > S)
    Remain -= S;
  else
    Remain = 0;
};

void OFiles::write(const BShifter *Buffer) {
  try {

    Fout->write(reinterpret_cast<const char *>(Buffer->BytePtr()),
                Buffer->size());

  } catch (const char *msg) {
    throw msg;
  }
}

const char *OFiles::get_name() const { return Name.c_str(); };
const size_t OFiles::size() const { return fileSize; };

OFiles::~OFiles() {
  try {

    std::tm tm = {};

    std::stringstream ss(lastEdit);

    ss >> std::get_time(&tm, "%b %d %Y %H:%M:%S");

    auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    std::chrono::time_point<std::chrono::file_clock> ftime(
        std::chrono::clock_cast<std::chrono::file_clock>(tp));

    std::filesystem::last_write_time(std::filesystem::path(Name),

                                     std::filesystem::file_time_type(ftime));

    Fout->clear();
    Fout->close();

    delete Fout;

  } catch (const char *msg) {
    throw msg;
  }
}
