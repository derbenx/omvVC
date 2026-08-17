how to use:
 install omv
 set up at least one shared folder
 install plugin
 install veracrypt (there is an install button in the plugin, or use apt install)
 storage -> disks; pick the device path with your container [ex; /dev/sdb]
 storage -> shared folder; pick the drive to mount the container to

 your 'container location' looks like;  /dev/sdb/path/to/container.vc
 your 'endpoint folder' looks like; /srv/dev-disk-by-uuid-XXX/folder/
 add your container password and press the mount button
 
 If mounted, it should show up in 'active mounts'
 You can enter the path or slot number and press the unmount button here

On the create container page, the container folder should be similar to /dev/sdb/path/to/contain.vc
