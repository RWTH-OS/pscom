/*
 * Author:
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/resource.h> // getrlimit

/* #include <sysfs/libsysfs.h> */

#include "list.h"
#ifndef IVSHMEM_DONT_USE_ZERO_COPY
#include "pscom_priv.h"
#endif
#include "pscom_util.h"
#include "perf.h"
#include "psivshmem.h"
#include <infiniband/verbs.h>


typedef struct ivshmem_pci_dev_s {
	int uioN_index;
	char name[50];
	char version[50];
	char str_map1_size_hex[50];
	long int map1_size_Byte;
	float  map1_size_MiB;
	void iv_shm_base;
	
} ivshmem_pci_dev_t;


static
int line_from_file(char *filename, char *linebuf) //from opensource... uio device info
{
	char *s;
	int i;
	memset(linebuf, 0, UIO_MAX_NAME_SIZE);
	FILE* file = fopen(filename,"r");
	if (!file) return -1;
	s = fgets(linebuf,UIO_MAX_NAME_SIZE,file);
	if (!s) return -2;
	for (i=0; (*s)&&(i<UIO_MAX_NAME_SIZE); i++) {
		if (*s == '\n') *s = 0;
		s++;
	}
	return 0;
}




int psivshmem_find_uio_device(ivshmem_pci_dev_t *dev)


    

    int n;
    int dev_fd;
    FILE* fd;
    char file_path[UIO_MAX_NAME_SIZE];    
    char device_name[UIO_MAX_NAME_SIZE];    
    char map_size[UIO_MAX_NAME_SIZE];    
    char version[UIO_MAX_NAME_SIZE];    


    char expectedDeviceName[20] = "ivshmem";

    for(n = 0; n<1001;n++)
    {
	
      	sprintf(file_path, "/sys/class/uio/uio%d/name", n);
      	
	fd = fopen(file_path, "r");  // Is any uioN file availabe? -> device is, too! 
	if (!fd){ goto no_device;}
	fclose(fd);	

    	line_from_file(file_path,dev->name);	// check name
	if (strncmp(dev->name, expectedDeviceName,7))  
	{
		printf("cont...");
		continue; // wrong device name -> try next
	}
    
	//if name suits try to open char_dev file and read dev_specs:
	

   	sprintf(file_path, "/dev/uio%d", n);
     	dev_fd = open(file_path);
	if (dev_fd == -1) {goto device_error;}
	


   	sprintf(file_path, "/sys/class/uio/uio%d/maps/map1/size", n);
    	line_from_file(file_path, dev->str_map1_size_hex);
   
     	printf("Map_Size \t= %s\n" , dev->str_map1_size_hex); 
    	dev->map1_size_Byte = strtol(dev->str_map1_size_hex, NULL, 0);

    	dev->map1_size_MiB   =  dev->map1_size_Byte / (float)1024 / (float)1024; // Byte -> KiB -> MiB

    	sprintf(file_path, "/sys/class/uio/uio%d/version", n);
    	line_from_file(file_path,dev->version);
   
 
        void *map_addr = mmap(NULL,dev->map1_size_Byte, PORT_READ | PORT_WRITE, MAP_SHARED, dev_fd,1 * getpagesize());  // last param. overloaded for ivshmem -> 2 memorysegments available; Reg.= 0;  Data = 1;
	
	//add map to device struct
	//
	//add Reg memory -> VM ID
	//
	//add version check
   /* 
     	printf("Device_infos:\n");
     	printf("Devicename \t= %s\n" ,dev->name); 
     	printf("Map_Size \t= %.2f MiB\n" , dev->map1_size_MiB); 
     	printf("Version \t= %s\n" ,dev->version); 
   */	


     	close(dev_fd);
    	fclose(fd);
	return 0;

    }


no_device:
    //fclose(fd); //quatsch, -> file konnte ja gar nicht geoeffnet werden!
    printf("no suitable pci dev\n");
    return -1;
device_error:
    printf("device not available")

}


#define META_MAGIC 20101992
#define META_MAGIC_OFFSET 10
#define META_LOCK_OFFSET 12  // ??!!
#define META_BITMAP_SIZE_OFFSET 14
#define BITMAP_OFFSET 16


#define IVSHMEM_FRAMESIZE 40 //in Byte
#define WORD_SIZE (CHAR_BIT * sizeof(int))
#define TOTAL_BITS 1000000
//#define SETBIT(b,n) ((b)[(n)/WORD_SIZE] |= (1 << ((n) % WORD_SIZE)))
#define SET_BIT(b,n) ((b)[(n)/WORD_SIZE] |= (1 << ((n) % WORD_SIZE)))
#define CLR_BIT(b,n)  ((b)[(n)/WORD_SIZE] &= ~(1 << ((n) % WORD_SIZE)))


int psivshmem_ceate_matadata(ivshme_pci_dev_t *dev)
{
  
    int n;
    int *magic = dev->iv_shm_base + META_MAGIC_OFFSET; 
    int *meta_lock = dev->iv_shm_base + META_LOCK_OFFSET;
    int *bitmap_size = dev->iv_shm_base + META_BITMAP_SIZE_OFFSET;	
    unsigned *bitmap = dev_iv_shm_base + BITMAP_OFFSET;

    

    if ( *magic == META_MAGIC)  // metadata already initilized
    {
    return -1;
    }
    
    while(*meta_lock);  // "active wait"   <- useless
    *meta_lock = 1;	// lock metadata
 
/*
 * 
 * totalNumberOfFrames = map1_size_Bayte / IVSHMEM_FRAMESIZE;
 * neededInts = totalNumberofFrames / BitsPerInt; 
 * int Bitmap[neededInts] 
 *
 * */


	
    int numOfFrames = (dev->map1_size_Byte / IVSHMEM_FRAMESIZE);
    if (dev->map1_size_Byte % IVSHMEM_FRAMESIZE) numOfFrames++;
    	

//    int Bitmap[neededInts];     
//    unsigned bitmap[TOTAL_BITS / WORD_SIZE +1] = {0};
/*
 *  size_t index  = nbit / (sizeof(bitmap_data_t) * 8);
 *      size_t bitpos = nbit % (sizeof(bitmap_data_t) * 8);
 *
 *
 * */
   

 // SETBIT(bitmap,50);
    
    
      //set own frames to: used!
      //make sure, that the BITMAP is always at the end of metadata!
    
     int metaDataSize = (BITMAP_OFFSET + *bitmap_size) / IVSHMEM_FRAMESIZE; 
     if ((BITMAP_OFFSET + *bitmap_size) / IVSHMEM_FRAMESIZE) metaDataSize += 1;  //?? runtim vs. memory!!
    
     for (n=0; n<metaDataSize; n++) 
     {
     SET_BIT(bitmap,n);  //Set FrameID = 1
     }

     
     *magic = META_MAGIC;
     *meta_lock = 0;
      
    

}

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

int test_alloc(ivshmem_pci_dev_t *dev, int size){
/*
 * first implementation: First Fit
 *
 * param: size = # of needed _frames_
 *
 * returns index of first free frame 
 * returns -1 if memory is filled
 *
 * */	


    int n;
    int cnt = 0;
    unsigned *bitmap = dev_iv_shm_base + BITMAP_OFFSET;

    for(n=0; n++;)  ///VGL LEGO -> find largest hole in wall...
    {
	if (CHECK_BIT(bitmap,n))
	{
	    cnt++;
	} else
	{
	    cnt = 0;
	}
	
	//check if pointer has a plausible value <-> ptr != 0
	
	// return index of first free frame belonging to a block of at least N free frames! 
	if (cnt >= (size) {
	return (n - cnt); // return index of first free frame belonging to a block of at least N free frames! 
	}
    }

    return -1; //not enough memory

}

int free_frame(ivshmem_pci_dev_t *dev, void * frame_ptr)
{
/*
 * first implementation: just clear corresponding bit in bitmap -> frame is available
 *
 * ToDo: add Mutex!!
 *
 * ToDo2: clear VM ID in every frame
 *
 */
    int n; 
    int index;
    unsigned *bitmap = dev->iv_shm_base + BITMAP_OFFSET;

    index = (frame_ptr _ dev->iv_shm_base) / IVSHMEM_FRAMESIZE;
    CLR_BIT(bitmap,index);

}

void *alloc_frame(ivshmem_pci_dev_t *dev)
{   
    int n = 0;
    int index = 0;
    const int frameQuantity= 1;    
    void *ptr = NULL;
    unsigned *bitmap = dev->iv_shm_base + BITMAP_OFFSET;
	

    index = test_alloc(dev, frameQuantity);    
    if(index == -1) return ptr;

	
    // MUTEX LOCK
   
    SET_BIT(bitmap,index);
    
    ptr = dev->iv_shm_base + index * (dev->map1_size_Byte / IVSHMEM_FRAMESIZE); // base + index * numberOfFrames

    // MUTEX UNLOCK

    return ptr;
    	

}

//ToDo: move frameSize to ivshmem_dev infos!

void *alloc_memory(ivshmem_pci_dev_t *dev, int sizeByte)
{
    int n;
    int index;
    int frame_qnt = 0;
    void *ptr = NULL;
    unsigned *bitmap = dev->iv_shm_base + BITMAP_OFFSET;

    frame_qnt = sizeByte / IVSHMEM_FRAMESIZE;
    if(sizeByte % IVSHMEM_FRAMESIZE) frame_qnt++; // one more frame if modulo != 0

	// MUTEX LOCK

    index = test_alloc(frame_qnt);
    if(index == -1) return ptr;  // error! not enough memory


    for (n = 0; n<frame_qnt; n++)
    {
	SET_BIT(bitmap,index);  //ToDo: macro to set more bits "at once"
	
    }
   
	// MUTEX UNLOCK
    
    ptr = dev->iv_shm_base + index * (dev->map1_size_Byte / IVSHMEM_FRAMESIZE); // base + index * numberOfFrames

    return ptr;
}

int unmap_device(ivshmem_pci_dev_t *dev)
{

/*
 * ToDO: implement functionallity to unmap the device memory from process user space!
 *
 */

    return -1;
}

//ToDo
/*
 * [void *alloc_frame(dev);]	//buffered ->only one frame
 * void *alloc_memory(dev, int sizeByte); 	//direct Mode -> returns more than one frame
 * [int free_frame(void *ptr);]
 * [int test_alloc(int size);] size in frames!
 * int unmap_device(--device);
 *
 * [ ... ] <=> done!
 *
 * ToDo:
 * 	implement: find out that VMs has been migrated ->change in Hostname, e.g.
 *
 *
 *
 */








/*
int main(){
	

 
   ivshmem_pci_dev_t  device;
    
   psivshmem_find_uio_device(&device);
	
   return;
}
*/
