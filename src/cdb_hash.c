/* Public domain. */

#include "cdb.h"

uint32 cdb_hashadd(uint32 h,unsigned char c)
{
  h += (h << 5);
  return h ^ c;
}

uint32 cdb_hash(const char *buf,unsigned int len)
{
  uint32 h;

  h = CDB_HASHSTART;
  while (len) {
    h = cdb_hashadd(h,*buf++);
    --len;
  }
  return h;
}
