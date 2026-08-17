how to use:
 install omv
 set up at least one shared folder
 install plugin
 install veracrypt (there is an install button in the plugin, or use apt install)
 storage -> shared folder;
  pick the device path with your container [ ex; /srv/dev-disk-by-uuid-###/ ]
  pick the drive to mount the container to [ ex; /srv/dev-disk-by-uuid-###/ ]

 your 'container location' looks like;  /srv/dev-disk-by-uuid-###/path/to/container.vc
 your 'endpoint folder' looks like; /srv/dev-disk-by-uuid-###/yourfolder/
 add your container password and press the mount button
 
 If mounted, it should show up in 'active mounts'
 You can enter the path or slot number and press the unmount button here

On the create container page, the container folder should be similar to /srv/dev-disk-by-uuid-###/path/to/contain.vc
