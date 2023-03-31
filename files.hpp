#include "BShifter.hpp"
#include <chrono>
#include <cmath>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static std::string err;

/*
 *#The GPLv3 License (GPLv3)

 Copyright (c) 2023 sigmAmaster

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
 * */

// header buffer size
#define HBS 512

struct IFiles {

  explicit IFiles(const char *name, std::uint64_t Id);
  ~IFiles();

  const std::shared_ptr<BShifter> header() const;

  void read(BShifter *);
  const size_t size() const;

  const size_t how_much_read() const;

  const char *get_name() const;
  const uint64_t get_id() const;

private:
  std::ifstream *Fin;
  void filter_name(const char *path);

  size_t fileSize;
  size_t Remain;
  uint64_t headSize;

  std::string Name;
  const std::uint64_t ID;

  template <typename TP> std::time_t to_time_t(TP tp) {
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now() +
                                                        system_clock::now());
    return system_clock::to_time_t(sctp);
  }

  std::shared_ptr<BShifter> Header;
};

struct OFiles {

  explicit OFiles(const char *name, const char *size, const char *lastedit);

  void write(const BShifter *Buffer);

  const char *get_name() const;

  void operator+=(size_t S);

  const size_t size() const;
  const std::uint64_t how_much_write() const;
  ~OFiles();

private:
  std::ofstream *Fout;

  size_t fileSize;
  size_t Remain;

  std::string Name;
  const char *lastEdit;
};
