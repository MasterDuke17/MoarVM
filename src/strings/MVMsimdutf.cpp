#include "simdutf.cpp"
#include "MVMsimdutf.h"

int MVM_string_is_valid_utf8(const char* str, size_t len) {
  return simdutf::validate_utf8(str, len);
}

int MVM_string_utf8_count(const char* str, size_t len) {
  return simdutf::count_utf8(str, len);
}

int MVM_string_utf8_length_from_latin1(const char* str, size_t len) {
  return simdutf::utf8_length_from_latin1(str, len);
}

int MVM_string_convert_latin1_to_utf8(const char* input, size_t len, char *output) {
  return simdutf::convert_latin1_to_utf8(input, len, output);
}
int MVM_string_convert_utf8_to_latin1(const char* input, size_t len, char *output) {
  return simdutf::convert_utf8_to_latin1(input, len, output);
}
