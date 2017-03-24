
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
