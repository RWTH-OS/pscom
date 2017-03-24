/*
 * Author: Jonas Baude
 */


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/resource.h> // getrlimit
//#ifndef IVSHMEM_DONT_USE_ZERO_COPY
#include "pscom_priv.h"
//#endif
#include "pscom_util.h"
#include "perf.h"
#include "psivshmem.h"
#include <semaphore.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>


int psivshmem_debug = 2;
FILE *psivshmem_debug_stream = NULL;

#define psivshmem_dprint(level,fmt,arg... )                                 	\
    do {                                                                	\
        if ((level) <= psivshmem_debug) {                                   	\
            fprintf(psivshmem_debug_stream ? psivshmem_debug_stream : stderr,   \
                    "ib:" fmt "\n",##arg);                              	\
        }                                                               	\
    } while(0);



static
int psreadline_from_file(char *fname, char *lbuf) //(filename, linebufer) 
{
	char *s;
	int i;
	memset(lbuf, 0, UIO_MAX_NAME_SIZE);
	FILE* file = fopen(fname,"r");
	if (!file) return -1;
	s = fgets(lbuf,UIO_MAX_NAME_SIZE,file);
	if (!s) return -2;
	for (i=0; (*s)&&(i<UIO_MAX_NAME_SIZE); i++) {
		if (*s == '\n') *s = 0;
		s++;
	}
	return 0;
}

int psivshmem_init_uio_device(ivshmem_pci_dev_t *dev) // init the device 
{
    int n;
    struct dirent **namelist;
    int dev_fd;
    FILE* fd;
    char file_path[UIO_MAX_NAME_SIZE];    
    char device_name[UIO_MAX_NAME_SIZE];    
    char map_size[UIO_MAX_NAME_SIZE];    
    char version[UIO_MAX_NAME_SIZE];    

    char expectedDeviceName[20] = "ivshmem";  // identify the ivshmem device by compareing the device name to 'ivshmem'


    n = scandir("/sys/class/uio", &namelist, 0, alphasort);
    if (n<0) goto no_device;

    while(n--) {
	
	//printf("n=%d",n);

	
	sprintf(file_path, "/sys/class/uio/%s/name", namelist[n]->d_name);
//	printf("file_path = %s", file_path);
	
//	fd = fopen(file_path, "r");  // Is any uioN file availabe? -> device is, too! 
//	if (!fd){ goto no_device;}
//	fclose(fd);	
// old implementation with for-loop


    	psreadline_from_file(file_path,dev->name);	// check name
	if (strncmp(dev->name, expectedDeviceName,7))  
	{
		//printf("cont...\n");
		free(namelist[n]);
		continue; // wrong device name -> try next
	}
    
	//if name suits try to open char_dev file and read dev_specs:

	sprintf(file_path, "/dev/%s", namelist[n]->d_name);
     	
	dev_fd = open(file_path, O_RDWR);
	if (dev_fd == -1) {goto device_error;}
	
   	sprintf(file_path, "/sys/class/uio/%s/maps/map1/size", namelist[n]->d_name);
    	psreadline_from_file(file_path, dev->str_map1_size_hex);
   
    //	printf("Map_Size \t= %s\n" , dev->str_map1_size_hex); 
    	dev->map1_size_Byte = strtol(dev->str_map1_size_hex, NULL, 0);

//	printf("size in ind byte=%lu\n",dev->map1_size_Byte);
	psivshmem_dprint(3, "Mapped Memory Size: %lu",dev->map1_size_Byte);

    	dev->map1_size_MiB   =  dev->map1_size_Byte / (float)1024 / (float)1024; // Byte -> KiB -> MiB

    	sprintf(file_path, "/sys/class/uio/%s/version", namelist[n]->d_name);

//    	psreadline_from_file(file_path,dev->version);
   
 
        void *map_addr = mmap(NULL,dev->map1_size_Byte, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd,1 * getpagesize());  // last param. overloaded for ivshmem -> 2 memorysegments available; Reg.= 0;  Data = 1;
	

	dev->metadata = (meta_data_t *) map_addr;  //map metadata!
	dev->iv_shm_base = map_addr; 

	if(dev->metadata->magic != META_MAGIC) goto not_initialised; 
	
   /* 
     	printf("Device_infos:\n");
     	printf("Devicename \t= %s\n" ,dev->name); 
     	printf("Map_Size \t= %.2f MiB\n" , dev->map1_size_MiB); 
	printf("iv_shm_base = %p\n", dev->iv_shm_base);   
	printf("Offset Address= %p\n", &dev->metadata->bitmapOffset);
*/
	
     	close(dev_fd); //keep dev_fd alive? --> no, mmap() saves required data internally, c.f.man pages
	free(namelist);
	return 0;

    }

not_initialised:
    DPRINT(1,"Unable to find initialised metadata\n");
    return -1;
no_device:
    DPRINT(1,"no suitable pci dev\n");
    return -1;
device_error:
    DPRINT(1,"device not available\n");
    return -1;

}


unsigned long test_alloc(ivshmem_pci_dev_t *dev, size_t size){
/*
 * first implementation: First Fit
 *
 * param: size = # of needed _frames_
 *
 * returns index of first free frame 
 * returns -1 if memory is filled
 *
 * */	


    long n;
    unsigned long cnt = 0;
    unsigned int  *bitmap =(unsigned int*) (dev->iv_shm_base + (unsigned long)dev->metadata->bitmapOffset);


    for(n=0; n< dev->metadata->numOfFrames; n++)
    {


//	printf("bitmap bit no %d = %d\n",n,CHECK_BIT(bitmap,n));

	if (!CHECK_BIT(bitmap,n))
	{
	    cnt++;
	} else
	{
	    cnt = 0;
	}
	

	
	// return index of first free frame belonging to a block of at least N free frames! 
	if (cnt >= size) {
	return (n - cnt + 1); // return index of first free frame belonging to a block of at least N free frames! 
	}
    }

    return -1; //not enough memory

}

int psivhmem_free_frame(ivshmem_pci_dev_t *dev, void * frame_ptr)
{
/*
 * first implementation: just clear corresponding bit in bitmap -> frame is available again
 *
 */
    long n; 
    long index;
    unsigned *bitmap = (unsigned int*)(dev->iv_shm_base + dev->metadata->bitmapOffset);

    index = (frame_ptr - dev->iv_shm_base) / dev->metadata->frameSize;
 
    while(sem_wait(&dev->metadata->meta_semaphore));

	CLR_BIT(bitmap,index);

    sem_post(&dev->metadata->meta_semaphore);
   
    return 0;

}

int psivshmem_free_mem(ivshmem_pci_dev_t *dev, void * frame_ptr, size_t size)
{
/*
 * first implementation: just clear corresponding bit in bitmap -> frame is available
 *
 * "a = b/c"  int division round up
 * int a = (b + (c - 1)) / c  <- rounds up for positiv int, e.g. frameIndices
 *
 *
 */
    long n; 
    long index_low, index_high;
    unsigned *bitmap = (unsigned int*)(dev->iv_shm_base + dev->metadata->bitmapOffset);

    index_low = (frame_ptr - dev->iv_shm_base) / dev->metadata->frameSize; //has to be a multiple of it!
    index_high = (frame_ptr - dev->iv_shm_base + size + (dev->metadata->frameSize - 1)) / dev->metadata->frameSize;
 
    while(sem_wait(&dev->metadata->meta_semaphore));

        for(n = index_low; n<=index_high;n++) {  //'unlock' all N used frames 	
	   
	    CLR_BIT(bitmap, n);
	    //printf("psivshmem_free_mem(): cleared bit no.: %d\n",n);
	   // psivshmem_dprint(4,"psivshmem_free_mem(): cleared bit no.: %d\n",n);
	}
   
     sem_post(&dev->metadata->meta_semaphore);

return 0;

}

/*void *alloc_frame(ivshmem_pci_dev_t *dev)
{   
    int n = 0;
    int index = 0;
    const int frameQuantity= 1;    
    void *ptr = NULL;
    unsigned *bitmap = (unsigned int*) (dev->iv_shm_base + dev->metadata->bitmapOffset);
	

    index = test_alloc(dev, frameQuantity);    
    if(index == -1) return ptr;

	
    while(sem_wait(&dev->metadata->meta_semaphore)); // mutex lock
   
    SET_BIT(bitmap,index);
    
    sem_post(&dev->metadata->meta_semaphore); //mutex unlock

    ptr = (void*)dev->iv_shm_base + index * dev->metadata->frameSize;

    

    return ptr;

} */


//ToDo: move frameSize to ivshmem_dev infos!

void *psivshmem_alloc_mem(ivshmem_pci_dev_t *dev, size_t sizeByte)
{
   long n;
   long index;
   long frame_qnt = 0;
   void *ptr = NULL;
   
   unsigned *bitmap = (unsigned int*) (dev->iv_shm_base + (long) dev->metadata->bitmapOffset);


    frame_qnt = (sizeByte + (dev->metadata->frameSize - 1)) / dev->metadata->frameSize;


    while(sem_wait(&dev->metadata->meta_semaphore));
    

    index = test_alloc(dev ,frame_qnt);

	DPRINT(5,"psivshmem_alloc_memory: index= %ld\n",index);

    if(index == -1) return ptr;  // error! not enough memory


    for (n = index; n<index + frame_qnt; n++)
    {
	SET_BIT(bitmap,n);  //ToDo: maybe possible: macro to set more bits "at once"
	
   	 //printf("psivshmem_alloc_memory says <SET_BIT no %d>\n",n);	
  	 DPRINT(5,"psivshmem_alloc_memory:  <SET_BIT no %ld>\n",n);

    }
    
    sem_post(&dev->metadata->meta_semaphore);
   
    ptr = (void*)((char*)dev->iv_shm_base + (long)(index * dev->metadata->frameSize));

//	printf("ivshmem base ptr = %p\n", dev->iv_shm_base);
//	printf("ivshmem mem ptr = %p\n",ptr);

    return ptr;
}

int psivshmem_unmap_device(ivshmem_pci_dev_t *dev)
{

/*
 * ToDO: implement functionallity to unmap the device memory from process user space!
 *
 */

    return -1;
}

