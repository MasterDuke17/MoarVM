#include "simdutf.cpp"
#include "MVMsimdutf.h"

int MVM_string_is_valid_utf8(const char* str, size_t len) {
  return simdutf::validate_utf8(str, len);
}
