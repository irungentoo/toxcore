/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020 The TokTok team.
 */
#include <sys/param.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>

#define LOG_TO_STDOUT 0

/**
 * This file contains the support code for using -finstrument-functions.
 *
 * If you link this into a program, e.g. a test program, that was compiled with
 * -finstrument-functions, it will print an indented execution trace. E.g.:
 *
 * @code
 * int g() { return 0; }
 * int f() { return g(); }
 * int main() { return f(); }
 * @endcode
 *
 * Compiling the above with instrumentation and linking it with this file will
 * result in the following output:
 *
 * @verbatim
 * -> main
 *  -> f
 *   -> g
 *   <- g
 *  <- f
 * <- main
 * @endverbatim
 *
 * There are a few filter options you can apply below. Note that you'll need
 * addr2line in your PATH for this to work.
 */
namespace {

class CString {
  char const *str_;

 public:
  // cppcheck-suppress noExplicitConstructor
  constexpr CString(char const *str) : str_(str) {}

  friend bool operator<(CString lhs, CString rhs) { return strcmp(lhs.str_, rhs.str_) < 0; }
};

template <std::size_t N>
bool contains(CString const (&array)[N], std::string const &str) {
  return std::binary_search(array, array + N, str.c_str());
}

struct Symbol {
  std::string const name;
  std::string const file;
};

/**
 * This array lists functions that should *not* appear in the trace.
 */
constexpr CString exclusions[] = {
    "__bswap_32", "logger_callback_log", "make_family", "make_proto", "make_socktype",
};

/**
 * This array lists source files that *should* appear in the trace.
 *
 * If this array is empty, all files are traced.
 */
constexpr CString filter_sources[] = {
    "onion.c",
    "onion_announce.c",
    "onion_client.c",
};

class ExecutionTrace {
  using Process = std::unique_ptr<FILE, decltype(&pclose)>;
  using File = std::unique_ptr<FILE, decltype(&fclose)>;

  std::string const exe = []() {
    std::array<char, PATH_MAX> result;
    ssize_t const count = readlink("/proc/self/exe", result.data(), result.size());
    assert(count > 0);
    return count > 0 ? std::string(result.data(), count) : "/proc/self/exe";
  }();

#if LOG_TO_STDOUT
  File const log_file{stdout, std::fclose};
#else
  File const log_file{std::fopen("trace.log", "w"), std::fclose};
#endif
  unsigned nesting = 0;
  std::map<void *, Symbol> symbols;

  static std::string sh(std::string cmd) {
    std::string result;
    Process pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
      return "<popen-failed>";
    }
    std::array<char, 128> buffer;
    while (std::fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
      result += buffer.data();
    }
    return result;
  }

  Symbol const &resolve(void *fn) {
    // Already in the cache.
    auto const found = symbols.find(fn);
    if (found != symbols.end()) {
      return found->second;
    }

    // 0x<64 bit number>\0
    std::array<char, 16 + 3> addr;
    std::snprintf(addr.data(), addr.size(), "0x%lx",
                  static_cast<unsigned long>(reinterpret_cast<uintptr_t>(fn)));

    std::string const output = sh("addr2line -fs -e " + exe + " " + addr.data());

    std::size_t const newline = output.find_first_of('\n');
    std::size_t const colon = output.find_first_of(':');

    std::string const sym = output.substr(0, newline);
    std::string const file = output.substr(newline + 1, colon - (newline + 1));

    auto const inserted = symbols.insert({fn, {sym, file}});
    return inserted.first->second;
  }

  void indent() const {
    for (unsigned i = 0; i < nesting; i++) {
      std::fputc(' ', log_file.get());
    }
  }

  void print(char const *prefix, Symbol const &sym) {
    indent();
    std::fprintf(log_file.get(), "%s %s (%s)\n", prefix, sym.name.c_str(), sym.file.c_str());
  }

  static bool excluded(Symbol const &sym) {
    if (sizeof(filter_sources) != 0) {
      if (!contains(filter_sources, sym.file)) {
        return true;
      }
    }
    return contains(exclusions, sym.name);
  }

 public:
  void enter(void *fn) {
    Symbol const &sym = resolve(fn);
    if (!excluded(sym)) {
      print("->", sym);
      ++nesting;
    }
  }

  void exit(void *fn) {
    Symbol const &sym = resolve(fn);
    if (!excluded(sym)) {
      --nesting;
      print("<-", sym);
    }
  }
};

// We leak this one.
static ExecutionTrace *trace;

}  // namespace

extern "C" void __cyg_profile_func_enter(void *this_fn, void *call_site)
    __attribute__((__no_instrument_function__));
void __cyg_profile_func_enter(void *this_fn, void *call_site) {
  if (trace == nullptr) {
    trace = new ExecutionTrace();
  }
  trace->enter(this_fn);
}

extern "C" void __cyg_profile_func_exit(void *this_fn, void *call_site)
    __attribute__((__no_instrument_function__));
void __cyg_profile_func_exit(void *this_fn, void *call_site) {
  assert(trace != nullptr);
  trace->exit(this_fn);
}
