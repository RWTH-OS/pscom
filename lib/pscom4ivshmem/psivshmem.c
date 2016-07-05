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
	
	printf("string_length=%d\n" ,  sprintf(file_path, "/sys/class/uio/uio%d/name", n));

	printf("file_path=%s!\n",file_path);      

	
	fd = fopen(file_path, "r");  // Is any uioN file availabe? -> device is, too! 
	printf("fd=%d\n",fd);
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
     	dev_fd = open(file_path, O_RDWR);
	if (dev_fd == -1) {goto device_error;}
	


   	sprintf(file_path, "/sys/class/uio/uio%d/maps/map1/size", n);
    	psreadline_from_file(file_path, dev->str_map1_size_hex);
   
    	printf("Map_Size \t= %s\n" , dev->str_map1_size_hex); 
    	dev->map1_size_Byte = strtol(dev->str_map1_size_hex, NULL, 0);

	printf("size in ind byte=%lu\n",dev->map1_size_Byte);

    	dev->map1_size_MiB   =  dev->map1_size_Byte / (float)1024 / (float)1024; // Byte -> KiB -> MiB

	printf("Marke A\n");

    	sprintf(file_path, "/sys/class/uio/uio%d/version", n);

	printf("Marke B\n");

//    	psreadline_from_file(file_path,dev->version);
   
	printf("trying to mmap()...");
 
        void *map_addr = mmap(NULL,dev->map1_size_Byte, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd,1 * getpagesize());  // last param. overloaded for ivshmem -> 2 memorysegments available; Reg.= 0;  Data = 1;
	
	printf("mmap() successfull!");

	dev->metadata = (meta_data_t *) map_addr;  //map metadata!
	dev->iv_shm_base = map_addr; 


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

     //	printf("Map_Size \t= %.2f MiB\n" , dev->map1_size_MiB); 

     	close(dev_fd); //keep dev_fd alive? --> no, mmap() saves required data internally, c.f.man pages
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

   // printf("test_alloc says <hello World!>\n");

    unsigned long n;
    unsigned long cnt = 0i;
    unsigned int  *bitmap =(unsigned int*) (dev->iv_shm_base + (unsigned long)dev->metadata->bitmapOffset);


   // printf("test_alloc says <size: %d>\n",size);

    for(n=0; n< dev->metadata->numOfFrames; n++)
    {


//    printf("test_alloc says <hello out of the loop:%d>\n",n);
//	printf("bitmap bit no %d = %d\n",n,CHECK_BIT(bitmap,n));

	if (!CHECK_BIT(bitmap,n))
	{
	    cnt++;
	} else
	{
	    cnt = 0;
	}
	
	//check if pointer has a plausible value <-> ptr != 0
	
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
 * first implementation: just clear corresponding bit in bitmap -> frame is available
 *
 * ToDo: add Mutex!!
 *
 * ToDo2: clear VM ID in every frame
 *
 */
    long n; 
    long index;
    unsigned *bitmap = (unsigned int*)(dev->iv_shm_base + dev->metadata->bitmapOffset);

    index = (frame_ptr - dev->iv_shm_base) / dev->metadata->frameSize;
 
    while(sem_wait(&dev->metadata->meta_semaphore));
	CLR_BIT(bitmap,index);
    sem_post(&dev->metadata->meta_semaphore);

}

int psivshmem_free_mem(ivshmem_pci_dev_t *dev, void * frame_ptr, size_t size)
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
    long n; 
    long index_low, index_high;
    unsigned *bitmap = (unsigned int*)(dev->iv_shm_base + dev->metadata->bitmapOffset);

    index_low = (frame_ptr - dev->iv_shm_base) / dev->metadata->frameSize; //has to be a multiple of it!
    index_high = (frame_ptr - dev->iv_shm_base + size + (dev->metadata->frameSize - 1)) / dev->metadata->frameSize;
 
    while(sem_wait(&dev->metadata->meta_semaphore));
        for(n = index_low; n<=index_high;n++) {  //'unlock' all N used frames 	
	    CLR_BIT(bitmap, n);
//	printf("psivshmem_free_mem(): cleared bit no.: %d\n",n);
	}
    sem_post(&dev->metadata->meta_semaphore);

return 0;

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

	
    while(sem_wait(&dev->metadata->meta_semaphore)); // mutex lock
   
    SET_BIT(bitmap,index);
    
    sem_post(&dev->metadata->meta_semaphore); //mutex unlock

    ptr = (void*)dev->iv_shm_base + index * dev->metadata->frameSize;

    

    return ptr;

}

//ToDo: move frameSize to ivshmem_dev infos!

void *psivshmem_alloc_mem(ivshmem_pci_dev_t *dev, size_t sizeByte)
{
   long n;
   long index;
   long frame_qnt = 0;
    void *ptr = NULL;
    unsigned *bitmap = (unsigned int*) (dev->iv_shm_base + (long) dev->metadata->bitmapOffset);


//    printf("psivshmem_alloc_memory says <hello World!>\n");

    frame_qnt = (sizeByte + (dev->metadata->frameSize - 1)) / dev->metadata->frameSize;

    while(sem_wait(&dev->metadata->meta_semaphore));

//    printf("psivshmem_alloc_memory says <locked the mutex>\n");
    

    index = test_alloc(dev ,frame_qnt);

//    printf("psivshmem_alloc_memory says <index = %d>\n",index);

    if(index == -1) return ptr;  // error! not enough memory


    for (n = index; n<index + frame_qnt; n++)
    {
	SET_BIT(bitmap,n);  //ToDo: maybe possible: macro to set more bits "at once"
	
//   	 printf("psivshmem_alloc_memory says <SET_BIT no %d>\n",n);
	
    }
    
    sem_post(&dev->metadata->meta_semaphore);
   
    ptr = (void*)((char*)dev->iv_shm_base + (long)(index * dev->metadata->frameSize));

//	printf("ivshmem base ptr = %p\n", dev->iv_shm_base);
//	printf("ivshmem mem ptr = %p\n",ptr);



//    printf("psivshmem_alloc_memory says <reached the end! :-) >\n");
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
