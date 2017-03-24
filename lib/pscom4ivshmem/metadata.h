/*
 * Author: JonBau
 */


#ifndef _METADATA_H_
#define _METADATA_H_

#include <semaphore.h>


typedef struct meta_data{
    
    int magic;
    sem_t meta_semaphore;
    char hostname[65];
    long memSize;
    long bitmapOffset;
    long numOfFrames;
    long frameSize;
    long metaSize; //Byte
    long bitmapLength;
}meta_data_t;

#define META_MAGIC 20101992

#endif /* _METADATA_H_ */
