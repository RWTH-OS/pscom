[![Build Status](https://travis-ci.org/RWTH-OS/pscom.svg?branch=sp%2Fadd-travis)](https://travis-ci.org/RWTH-OS/pscom)

# pscom

## Suspending / Resuming

This fork extends [ParaStation/pscom](https://github.com/ParaStation/pscom) by support for suspending/resuming conncections including feedback via MQTT.


## Inter-VM Shared Memory Communication

This fork also extends [ParaStation/pscom](https://github.com/ParaStation/pscom) by support for inter-vm shared memory communication over virtaul pci devices.

The new interconnect is implemented in the ivshmem plugin (*lib/pscom4ivshmem*).
The following steps are based on the combination of libvirt 2.5.0 and qemu 2.6.0 - make sure to use adequate vms.

The *vendor/ivshmem* directory provides: 
 * uio kernel module for ivshmem devices
 * udev rule for ivshmem device 
 * sysconfig module to load uio-framework and the ivshmem driver at boottime
 * hotplug device file
 * hostserver process

### VM Modifications

Compile the provided ivshmem uio driver and install it (to */lib/modules/[kernel version]/kernel/drivers/uio*).
 
```
$ cd vendor/ivshmem/driver
$ make
$ sudo make install

```

Insert an appropriate udev .rules file into the */etc/udev/rules.d* directory to give read and write access to the */dev/uioN* device file.
An example rule file is located in *vendor/ivshmem/udev*

```
$ sudo cp ./vendor/ivshmem/udev/ivshmem-uio-device.rules /etc/udev/rules.d/

```

In order to load the uio framework and the ivshmem driver at boot time, an appropriate sysconfig module under */etc/sysconfig/modules* is necessary.
An example module is locatd in *vendor/ivshmem/sysconfig*

```
$ sudo cp ./vendor/ivshmem/sysconfig/ivshmem-uio.modules /etc/sysconfig/modules/

```


### Host Server Process

The current ivshmem plugin requires a server process that is executed directly on the underlaying host node.

The server can simply be build by:

```
$ cd ./vendor/ivshmem/server/
$ make all

```

The server is used as shown below:

```
$ ./ivshmem-server -s <host-shm-name> -m <size> -c migration-framework

```

with:
-s = name of the shared memory segment on the host - it has to match the "shmem name" definded in the shmem device .xml file!
-m = size of the shared memory segment in MB (has to be a multiple to the power of 2)
-c = customization mode;  use migration-framework 


### IVSHMEM Device

The syntax for ivshmem device definition is:
```
<shmem name='ivshmem0'>
    <model type='ivshmem-plain'/>
    <size unit='M'>512</size>
    <alias name='ivshmem0'/>
</shmem>

```

This .xml snippet can be added the the libvirt domain representation file vm-xy.xml ( `$ virsh edit vm-xy`) or it can be attached to the vm at runtime.

*Note: The <shmem name> has to match the host shared memory region that the server process is using.*

### IVSHMEM Device Hot(un)plug

The ivshmem device can be hotpluged and -unpluged with libvirt 2.5.0 as follows:

```
$ virsh attach-device vm-xy /path/to/pscom/vendor/ivshmem/hotplug/device001.xml

$ virsh detach-device vm-xy /path/to/pscom/vendor/ivshmem/hotplug/device001.xml

```

*Note: Migration is blocked while ivshmem devices are attached to a vm. Detach the device, migrate the vm and attach an ivshmem device again (if still required after migration)*

### Example Setup
To use two vms on one host with ivshmem support, simply do the following:

* start the server process
  ```
  $ ./ivshmem-server -s ivshmem0 -m 512 - c migration-framework

  ```

* start two virtual machines, eg. vm-x1 and vm-x2
  ```
  $ virsh start vm-x1
  $ virsh start vm-x2

  ```

* attach the device the the vms. Make sure the device name and size match the server arguments.
  ```
  $ virsh attach-device vm-x1 /path/2/pscom/vendor/ivshmem/hotplug/device1.xml
  $ virsh attach-device vm-x2 /path/2/pscom/vendor/ivshmem/hotplug/device1.xml

  ```

* *optional* check inside the vms:
  ```
  $ ll /dev/uio*

  ```
* now the ivshmem plugin should work and pscom connections between co-located vms will be established via ivshmem.

*Note: Start the serverprocess before booting the virtual machines! Otherweise qemu creates a host shared memory segment that can only be accessed with __root rights__.* 
