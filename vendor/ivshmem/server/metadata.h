
#include "metastruct.h"  //common struct for metadata -> keep equal to com lib struct!
#include <limits.h>


#define META_MAGIC 20101992
//#define META_MAGIC_OFFSET 10
//#define META_LOCK_OFFSET 12  // ??!!
//#define META_BITMAP_SIZE_OFFSET 14
//#define BITMAP_OFFSET 16


//#define IVSHMEM_FRAMESIZE 40 //in Byte
#define WORD_SIZE (CHAR_BIT * sizeof(int))
//#define TOTAL_BITS 1000000
//#define SETBIT(b,n) ((b)[(n)/WORD_SIZE] |= (1 << ((n) % WORD_SIZE)))

#define SET_BIT(b,n) ((b)[(n)/WORD_SIZE] |= (1 << ((n) % WORD_SIZE)))
#define CLR_BIT(b,n)  ((b)[(n)/WORD_SIZE] &= ~(1 << ((n) % WORD_SIZE)))

//#define META_MAP_SIZE 1024



//OFFSETS   not needed any more <-- strct instead

//#define MAGIC_OFFSET 0
//#define MUTEX_OFFSET 4 
//#define SIZE_OFFSET 20
//#define BITMAP_OFFSET 24
//#define BITMAP_SIZE_OFFSET 40   //check out sem size and adapt!

#define FRAME_SIZE 4096 //in Byte

