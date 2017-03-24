/*
 * A stand-alone shared memory server for inter-VM shared memory for KVM
*/

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "send_scm.h"
#include <semaphore.h> //<--
#include <limits.h>

#define DEFAULT_SOCK_PATH "/tmp/ivshmem_socket"
#define DEFAULT_SHM_OBJ "ivshmem"

#define DEBUG 1

#include "metadata.h"


typedef struct server_state {
    vmguest_t *live_vms;
    int nr_allocated_vms;
    long shm_size;
    long live_count;
    long total_count;
    int shm_fd;
    char * path;
    char * shmobj;
    char * customized;
    int maxfd, conn_socket;
    long msi_vectors;
} server_state_t;


void usage(char const *prg);
int find_set(fd_set * readset, int max);
void print_vec(server_state_t * s, const char * c);

void add_new_guest(server_state_t * s);
void parse_args(int argc, char **argv, server_state_t * s);
int create_listening_socket(char * path);

int create_metadata_for_pscom(server_state_t *s)
{
  
    void *map_region = NULL;
    meta_data_t *meta_data;
    unsigned int *bitmap;
    char hostname[65];
    long int size;

    hostname[64] = '\0';
    gethostname(hostname,64);	
   

    size = s->shm_size;//sizeof(meta_data_t)+16390;  // TO DO: calc bitmap size!
	
    if ((map_region=mmap(NULL,size, PROT_READ|PROT_WRITE, MAP_SHARED, s->shm_fd, 0))<0){
 
 	    fprintf(stderr, "ERROR: cannot mmap file\n");
	    return -1;
    }
	

    meta_data =(meta_data_t*)map_region;
    sem_t *mutex = &meta_data->meta_semaphore;  // use semaphore as mutex  //make reference shorter
  
  
    sem_init(mutex,1,1);

    while(sem_wait(mutex)); //wait for mutex // should usually be the only one!   

    meta_data->magic = META_MAGIC; 
    meta_data->bitmapOffset = sizeof(meta_data_t); 
    strcpy(meta_data->hostname, hostname);
    meta_data->memSize = s->shm_size;
    meta_data->frameSize = FRAME_SIZE;
    meta_data->numOfFrames = meta_data->memSize / FRAME_SIZE;
    if (meta_data->memSize % FRAME_SIZE) meta_data->frameSize++;  // one smaller frame es 'rest'

    bitmap = map_region + meta_data->bitmapOffset; // ToDO: make size more portable
            
      //set own frames to: used!
      //make sure, that the BITMAP is always at the end of metadata!
    
 
    //bitmap size = NumOfFrames / 32 = numInt32 = numInts

    int BitmapSize = meta_data->numOfFrames / (sizeof(unsigned int)*CHAR_BIT);  
        if (meta_data->numOfFrames % sizeof(unsigned int)*CHAR_BIT) BitmapSize++;  
    
    int metaDataFrames = (sizeof(meta_data_t)+ BitmapSize * sizeof(unsigned int)) / FRAME_SIZE;
	if( (sizeof(meta_data_t)+ BitmapSize * sizeof(unsigned int)) % FRAME_SIZE) metaDataFrames++;
     
    meta_data->metaSize = sizeof(meta_data_t) + BitmapSize * sizeof(unsigned int);

	
    long n;

    for(n=0; n<BitmapSize; n++){
    bitmap[n] = 0;  // reset bitmap
    }

    for (n=0; n<metaDataFrames; n++) 
    {
     SET_BIT(bitmap,n);  //mark all(loop) frames which are used for meta_data 
    }

    
    sem_post(mutex);   
    munmap(map_region,size);

    printf("Succsessfully created metadata block!\n");    
  
    return 0;

}



int main(int argc, char ** argv)
{
    printf("%ld\n",sizeof(unsigned int)*CHAR_BIT);
    fd_set readset;
    server_state_t * s;

    s = (server_state_t *)calloc(1, sizeof(server_state_t));

    s->live_count = 0;
    s->total_count = 0;
    parse_args(argc, argv, s);

    /* open shared memory file  */
    if ((s->shm_fd = shm_open(s->shmobj, O_CREAT|O_RDWR, S_IRWXU)) < 0)
    {
        fprintf(stderr, "ivshmem server: could not open shared file\n");
        exit(-1);
    }

    if (ftruncate(s->shm_fd, s->shm_size) != 0)
    {
        fprintf(stderr, "ivshmem server: could not truncate memory region\n");
        exit(-1);
    }

/*************************************************************************************************/

	    if(!strcmp(s->customized,"migration-framework")||!strcmp(s->customized, "pscom")){
 	    create_metadata_for_pscom(s);
	    }

/*************************************************************************************************/

    s->conn_socket = create_listening_socket(s->path);

    s->maxfd = s->conn_socket;

    for(;;) {
        int ret, handle, i;
        char buf[1024];

        print_vec(s, "vm_sockets");

        FD_ZERO(&readset);
        /* conn socket is in Live_vms at posn 0 */
        FD_SET(s->conn_socket, &readset);
        for (i = 0; i < s->total_count; i++) {
            if (s->live_vms[i].alive != 0) {
                FD_SET(s->live_vms[i].sockfd, &readset);
            }
        }

        printf("\nWaiting (maxfd = %d)\n", s->maxfd);

        ret = select(s->maxfd + 1, &readset, NULL, NULL, NULL);

        if (ret == -1) {
            perror("select()");
        }

        handle = find_set(&readset, s->maxfd + 1);
        if (handle == -1) continue;

        if (handle == s->conn_socket) {

            printf("[NC] new connection\n");
            FD_CLR(s->conn_socket, &readset);

            /* The Total_count is equal to the new guests VM ID */
            add_new_guest(s);

            /* update our the maximum file descriptor number */
            s->maxfd = s->live_vms[s->total_count - 1].sockfd > s->maxfd ?
                            s->live_vms[s->total_count - 1].sockfd : s->maxfd;

            s->live_count++;
            printf("Live_count is %ld\n", s->live_count);

        } else {
            /* then we have received a disconnection */
            int recv_ret;
            long i, j;
            long deadposn = -1;

            recv_ret = recv(handle, buf, 1, 0);

            printf("[DC] recv returned %d\n", recv_ret);

            /* find the dead VM in our list and move it do the dead list. */
            for (i = 0; i < s->total_count; i++) {
                if (s->live_vms[i].sockfd == handle) {
                    deadposn = i;
                    s->live_vms[i].alive = 0;
                    close(s->live_vms[i].sockfd);

                    for (j = 0; j < s->msi_vectors; j++) {
                        close(s->live_vms[i].efd[j]);
                    }

                    free(s->live_vms[i].efd);
                    s->live_vms[i].sockfd = -1;
                    break;
                }
            }

            for (j = 0; j < s->total_count; j++) {
                /* update remaining clients that one client has left/died */
                if (s->live_vms[j].alive) {
                    printf("[UD] sending kill of fd[%ld] to %ld\n",
                                                                deadposn, j);
                    sendKill(s->live_vms[j].sockfd, deadposn, sizeof(deadposn));
                }
            }

            s->live_count--;

            /* close the socket for the departed VM */
            close(handle);
        }

    }

    return 0;
}

void add_new_guest(server_state_t * s) {

    struct sockaddr_un remote;
    socklen_t t = sizeof(remote);
    long i, j;
    int vm_sock;
    long new_posn;
    long neg1 = -1;

    vm_sock = accept(s->conn_socket, (struct sockaddr *)&remote, &t);

    if ( vm_sock == -1 ) {
        perror("accept");
        exit(1);
    }

    new_posn = s->total_count;

    if (new_posn == s->nr_allocated_vms) {
        printf("increasing vm slots\n");
        s->nr_allocated_vms = s->nr_allocated_vms * 2;
        if (s->nr_allocated_vms < 16)
            s->nr_allocated_vms = 16;
        s->live_vms = realloc(s->live_vms,
                    s->nr_allocated_vms * sizeof(vmguest_t));

        if (s->live_vms == NULL) {
            fprintf(stderr, "realloc failed - quitting\n");
            exit(-1);
        }
    }

    s->live_vms[new_posn].posn = new_posn;
    printf("[NC] Live_vms[%ld]\n", new_posn);
    s->live_vms[new_posn].efd = (int *) malloc(sizeof(int));
    for (i = 0; i < s->msi_vectors; i++) {
        s->live_vms[new_posn].efd[i] = eventfd(0, 0);
        printf("\tefd[%ld] = %d\n", i, s->live_vms[new_posn].efd[i]);
    }
    s->live_vms[new_posn].sockfd = vm_sock;
    s->live_vms[new_posn].alive = 1;


    sendPosition(vm_sock, new_posn);
    sendUpdate(vm_sock, neg1, sizeof(long), s->shm_fd);
    printf("[NC] trying to send fds to new connection\n");
    sendRights(vm_sock, new_posn, sizeof(new_posn), s->live_vms, s->msi_vectors);

    printf("[NC] Connected (count = %ld).\n", new_posn);
    for (i = 0; i < new_posn; i++) {
        if (s->live_vms[i].alive) {
            // ping all clients that a new client has joined
            printf("[UD] sending fd[%ld] to %ld\n", new_posn, i);
            for (j = 0; j < s->msi_vectors; j++) {
                printf("\tefd[%ld] = [%d]", j, s->live_vms[new_posn].efd[j]);
                sendUpdate(s->live_vms[i].sockfd, new_posn,
                        sizeof(new_posn), s->live_vms[new_posn].efd[j]);
            }
            printf("\n");
        }
    }

    s->total_count++;
}

int create_listening_socket(char * path) {

    struct sockaddr_un local;
    int len, conn_socket;

    if ((conn_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, path);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(conn_socket, (struct sockaddr *)&local, len) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(conn_socket, 5) == -1) {
        perror("listen");
        exit(1);
    }

    return conn_socket;

}

void parse_args(int argc, char **argv, server_state_t * s) {

    //
    //	
    // toDo: Add argument to decide whether user wants to create metadata or not!
    //
    //
    //

    int c;

    s->shm_size = 1024 * 1024; // default shm_size
    s->path = NULL;
    s->shmobj = NULL;
    s->msi_vectors = 1;

	while ((c = getopt(argc, argv, "hp:s:m:n:c:")) != -1) {

        switch (c) {
            // path to listening socket
            case 'p':
                s->path = optarg;
                break;
            // name of shared memory object
            case 's':
                s->shmobj = optarg;
                break;
            // size of shared memory object
            case 'm': {
                    uint64_t value;
                    char *ptr;

                    value = strtoul(optarg, &ptr, 10);
                    switch (*ptr) {
                    case 0: case 'M': case 'm':
                        value <<= 20;
                        break;
                    case 'G': case 'g':
                        value <<= 30;
                        break;
                    default:
                        fprintf(stderr, "qemu: invalid ram size: %s\n", optarg);
                        exit(1);
                    }
                    s->shm_size = value;
                    break;
                }
            case 'n':
                s->msi_vectors = atol(optarg);
                break;
	    case 'c':  //customized
		s->customized = optarg;
		break;
            case 'h':
            default:
	            usage(argv[0]);
		        exit(1);
		}
	}

    if (s->path == NULL) {
        s->path = strdup(DEFAULT_SOCK_PATH);
    }

    printf("listening socket: %s\n", s->path);

    if (s->shmobj == NULL) {
        s->shmobj = strdup(DEFAULT_SHM_OBJ);
    }

    printf("shared object: %s\n", s->shmobj);
    printf("shared object size: %ld (bytes)\n", s->shm_size);

}

void print_vec(server_state_t * s, const char * c) {

    int i, j;

#if DEBUG
    printf("%s (%ld) = ", c, s->total_count);
    for (i = 0; i < s->total_count; i++) {
        if (s->live_vms[i].alive) {
            for (j = 0; j < s->msi_vectors; j++) {
                printf("[%d|%d] ", s->live_vms[i].sockfd, s->live_vms[i].efd[j]);
            }
        }
    }
    printf("\n");
#endif

}

int find_set(fd_set * readset, int max) {

    int i;

    for (i = 1; i < max; i++) {
        if (FD_ISSET(i, readset)) {
            return i;
        }
    }

    printf("nothing set\n");
    return -1;

}

void usage(char const *prg) {
	fprintf(stderr, "use: %s [-h]  [-p <unix socket>] [-s <shm obj>] "
            "[-m <size in MB>] [-n <# of MSI vectors>] [-c <customization mode: eg. migration-framework>]\n", prg);
}
