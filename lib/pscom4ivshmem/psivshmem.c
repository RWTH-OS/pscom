/*
 * Author: JonBau
 */


#include <stdio.h>
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

int psivshmem_init_uio_device(ivshmem_pci_dev_t *dev) // init the right (!) device 
{
    int n;
    int dev_fd;
    FILE* fd;
    char file_path[UIO_MAX_NAME_SIZE];    
    char device_name[UIO_MAX_NAME_SIZE];    
    char map_size[UIO_MAX_NAME_SIZE];    
    char version[UIO_MAX_NAME_SIZE];    


    char expectedDeviceName[20] = "ivshmem";

    for(n = 0; n<1001;n++) //avoid infinite loop
    {
	
      	sprintf(file_path, "/sys/class/uio/uio%d/name", n);
      	
	fd = fopen(file_path, "r");  // Is any uioN file availabe? -> device is, too! 
	if (!fd){ goto no_device;}
	fclose(fd);	

    	psreadline_from_file(file_path,dev->name);	// check name
	if (strncmp(dev->name, expectedDeviceName,7))  
	{
		printf("cont...\n");
		continue; // wrong device name -> try next
	}
    
	//if name suits try to open char_dev file and read dev_specs:
	

   	sprintf(file_path, "/dev/uio%d", n);
     	dev_fd = open(file_path);
	if (dev_fd == -1) {goto device_error;}
	


   	sprintf(file_path, "/sys/class/uio/uio%d/maps/map1/size", n);
    	psreadline_from_file(file_path, dev->str_map1_size_hex);
   
     	printf("Map_Size \t= %s\n" , dev->str_map1_size_hex); 
    	dev->map1_size_Byte = strtol(dev->str_map1_size_hex, NULL, 0);

    	dev->map1_size_MiB   =  dev->map1_size_Byte / (float)1024 / (float)1024; // Byte -> KiB -> MiB

    	sprintf(file_path, "/sys/class/uio/uio%d/version", n);
    	psreadline_from_file(file_path,dev->version);
   
 
        void *map_addr = mmap(NULL,dev->map1_size_Byte, PORT_READ | PORT_WRITE, MAP_SHARED, dev_fd,1 * getpagesize());  // last param. overloaded for ivshmem -> 2 memorysegments available; Reg.= 0;  Data = 1;
	

	dev->metadata = (meta_data_t *) map_addr;  //map metadata!

	if(dev->metadata->magic != META_MAGIC) goto not_initialised; 
	

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


    // 	close(dev_fd); //keep dev_fd alive!
    	fclose(fd);
	return 0;

    }

not_initialised:
    printf("Unable to find initialised metadata\n");
    return -1;
no_device:
    //fclose(fd); //quatsch, -> file konnte ja gar nicht geoeffnet werden!
    printf("no suitable pci dev\n");
    return -1;
device_error:
    printf("device not available\n");
    return -1;

}


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


    unsigned int n;
    int cnt = 0;
    unsigned *bitmap =(unsigned int*) (dev->iv_shm_base + dev->metadat->bitmapOffset);

    for(n=0; n< dev->metadata->numOfFrames; n++;)
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
	if (cnt >= size) {
	return (n - cnt); // return index of first free frame belonging to a block of at least N free frames! 
	}
    }

    return -1; //not enough memory

}

int psivhmem_free_frame(ivshmem_pci_dev_t *dev, void * frame_ptr)
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
    unsigned *bitmap = (unsigned int*)(dev->iv_shm_base + dev->metadata->bitmapOffset);

    index = (frame_ptr - dev->iv_shm_base) / dev->metadata->frameSize;
 
    while(sem_wait(&dev->metadata->semaphore));
	CLR_BIT(bitmap,index);
    sem_post(&dev->metadata->semaphore);

}

int psivhmem_free_mem(ivshmem_pci_dev_t *dev, void * frame_ptr, int size)
{
/*
 * first implementation: just clear corresponding bit in bitmap -> frame is available
 *
 * [---ToDo2: clear VM ID in every frame---]
 *
 * "a = b/c"  int division round up
 * int a = (b + (c - 1)) / c  <- rounds up for positiv int, e.g. frameIndices
 *
 *
 */
    int n; 
    int index_low, index_high;
    unsigned *bitmap = (unsigned int*)(dev->iv_shm_base + dev->metadata->bitmapOffset);

    index_low = (frame_ptr - dev->iv_shm_base) / dev->metadata->frameSize; //has to be a multiple of it!
    index_high = (frame_ptr - dev->iv_shm_base + size + (dev->metadata->frameSize - 1)) / dev->metadata->frameSize;
 
    while(sem_wait(&dev->metadata->semaphore));
        for(n = index_low; n<=index_high;n++) {  //'unlock' all N used frames 	
	    CLR_BIT(bitmap, n);
	}
    sem_post(&dev->metadata->semaphore);

}

void *alloc_frame(ivshmem_pci_dev_t *dev)
{   
    int n = 0;
    int index = 0;
    const int frameQuantity= 1;    
    void *ptr = NULL;
    unsigned *bitmap = (unsigned int*) (dev->iv_shm_base + dev->metadata->bitmapOffset);
	

    index = test_alloc(dev, frameQuantity);    
    if(index == -1) return ptr;

	
    while(sem_wait(&dev->metadata->semaphore)); // mutex lock
   
    SET_BIT(bitmap,index);
    
    sem_post(&dev->metadata->semaphore); //mutex unlock

    ptr = (void*)dev->iv_shm_base + index * dev->metadata->frameSize;

    

    return ptr;

}

//ToDo: move frameSize to ivshmem_dev infos!

void *psivshmem_alloc_memory(ivshmem_pci_dev_t *dev, int sizeByte)
{
    int n;
    int index;
    int frame_qnt = 0;
    void *ptr = NULL;
    unsigned *bitmap = (unsigned int*) (dev->iv_shm_base + dev->metadata->bitmapOffset);

    frame_qnt = dev->metadata->numOfFrames;

    while(sem_wait(&dev->metadata->semaphore);

    index = test_alloc(frame_qnt);
    if(index == -1) return ptr;  // error! not enough memory


    for (n = 0; n<frame_qnt; n++)
    {
	SET_BIT(bitmap,index);  //ToDo: maybe possible: macro to set more bits "at once"
	
    }
    
    sem_post(&dev->metadata->semaphore);
   
    ptr = (void*)(dev->iv_shm_base + index * dev->metadata->frameSize);

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
