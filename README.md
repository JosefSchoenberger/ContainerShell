# ContainerShell

This provides a tool to run any shell in an containerized environment.

# How to use

`cargo run <base-dir> <cgroup-name> <cmd>`

\<base-dir\> needs to be a path to a directory, which is a copied and then used as the new root. Make sure to have all necessary utils installed in it.

\<cgroup-name\> needs to be the canonical name of a v2 cgroup. Make sure that you have sufficient rights to add a process to the corresponding cgroup.procs file (See [the Kernel Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#delegation-containment)) and that the cgroup has been configured correctly. 
Configuration would usually require superuser rights and thus is not done by this tool. See `man 7 cgroups` for more information.

\<cmd\> is the command to execute inside the container. This usually is a shell like `sh`, but you may choose to execute other commands.

## Getting a valid base file

To test ContainerShell, I recommend the use of busybox. To use it, make sure you have busybox-static installed, then create your new base-dir and run these commands inside:

```bash
mkdir bin
cp $(which busybox) .
mv busybox bin/sh
```
