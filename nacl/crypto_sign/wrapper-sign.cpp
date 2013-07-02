#include <string>
using std::string;
#include "crypto_sign.h"

string crypto_sign(const string &m_string, const string &sk_string)
{
  if (sk_string.size() != crypto_sign_SECRETKEYBYTES) throw "incorrect secret-key length";
  size_t mlen = m_string.size();
  unsigned char m[mlen+crypto_sign_BYTES];
  unsigned long long smlen;
  for (int i = 0;i < mlen;++i) m[i] = m_string[i];
  crypto_sign(
      m, 
      &smlen, 
      m, 
      mlen, 
      (const unsigned char *) sk_string.c_str()
      );
  return string(
      (char *) m,
      smlen
  );
}
