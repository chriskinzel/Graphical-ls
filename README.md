# Graphical ls
Graphical ls - shows a tree of all of the files in a directory, and recursively, all of the files in each directory it contains. Tree contains information for each entry it finds such as name, size on disk, and type (i.e. character device, regular file, etc..). An md5 checksum is printed for all regular files, for symbolic links the contents of the symlink are printed (i.e. where it points to) and the absolute path of that location. If an error is encountered at any point during operation the offending entry is skipped and an error message will be printed indicating the cause of failure for that entry. When no directory path is specified the current working directory is assumed.  
  
Program usage demonstrating how to run the program is given below.
  
    usage: 'gls [-ah] [directory_name]'  
       a : show hidden files and directories  
       h : display file sizes in human readable format (i.e. KB, MB, GB)  
  
    example:  
        ./gls -h /Users/Me/Desktop  

# Compilation
    gcc -Wall -lssl -lcrypto gls.c -o gls  
  