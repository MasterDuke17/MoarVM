#include <stddef.h>

#ifdef __cplusplus
extern "C"
#endif
int MVM_string_is_valid_utf8(const char* str, size_t len);

#ifdef __cplusplus
extern "C"
#endif
int MVM_string_utf8_count(const char* str, size_t len);

#ifdef __cplusplus
extern "C"
#endif
int MVM_string_utf8_length_from_latin1(const char* str, size_t len);

#ifdef __cplusplus
extern "C"
#endif
int MVM_string_convert_latin1_to_utf8(const char* input, size_t len, char *output);
