//
// Assignment 1 - Part A - gls
// ---------------------------------------------------------------------------------------------------
//
// Name:            Chris Kinzel
// Tutorial:                 T03
// ID:                  10160447
//
//  gls.c
//
//  compile with:
//      Linux:  gcc -Wall -lssl -lcrypto gls.c -o gls
//      OS X:   gcc -Wall gls.c -o gls
//
//
// Description:
// ---------------------------------------------------------------------------------------------------
//
// Graphical ls - shows a tree of all of the files in a directory, and recursively,
// all of the files in each directory it contains. Tree contains information for
// each entry it finds such as name, size on disk, and type (i.e. character device,
// regular file, etc..). An md5 checksum is printed for all regular files, for
// symbolic links the contents of the symlink are printed (i.e. where it points to)
// and the absolute path of that location. If an error is encountered at any point
// during operation the offending entry is skipped and an error message will be
// printed indicating the cause of failure for that entry. When no directory path
// is specified the current working directory is assumed.
//
//
// usage: 'gls [-ah] [directory_name]'
//     a : show hidden files and directories
//     h : display file sizes in human readable format (i.e. KB, MB, GB)
//
//
// All work in this assignment is my own other than the cited out of class resources.
// I have previous experience in C so I mostly consulted the man pages.
//
//
// Citations:
// ---------------------------------------------------------------------------------------------------
//   -  The following source was used to help me figure out how to use OpenSSL for MD5 hashing of a
//      file
//
//      http://stackoverflow.com/questions/10324611/how-to-calculate-the-md5-hash-of-a-large-file-in-c
//
//   -  I used the online linux man pages extensively in this assignment
//
//      http://man7.org/linux/man-pages/index.html
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>


#define VERSION "1.0"


#ifdef __APPLE__

    // Used to test the code on my personal machine

    // Starting with OS X Yosemite Apple removed the OpenSSL developement headers and
    // switched to using their own CommonCrypto library to replace OpenSSL. Luckily
    // CommonCrypto has an almost identical interface to OpenSSL which allows this
    // simple hack below to emulate some of the OpenSSL MD5 interface using the
    // CommonCrypto MD5 hash functions

    #include <CommonCrypto/CommonCrypto.h>

    #define MD5_DIGEST_LENGTH CC_MD5_DIGEST_LENGTH

    typedef CC_MD5_CTX MD5_CTX;

    // Function pointers to map OpenSSL MD5 hash functions to CommonCrypto
    // MD5 hash functions
    static int(* const MD5_Init)(MD5_CTX*) = CC_MD5_Init;
    static int(* const MD5_Update)(MD5_CTX*, const void*, unsigned int) = CC_MD5_Update;
    static int(* const MD5_Final)(unsigned char*, MD5_CTX*) = CC_MD5_Final;

#elif defined __linux__
    #include <openssl/md5.h>
#elif
    #error Missing crypto library for MD5 hash (OpenSSL or CommonCrypto required)
#endif



/* -------- GLOBAL VARIABLES -------- */

// Stores function to use to filter directory entries when using scandir()
static int(* filter_function)(const struct dirent*);

// Stores function to convert number of bytes into string
static char*(* byte_formatter)(long long);


/* -------- END GLOBAL VARIABLES -------- */



// Converts d_type filed of struct dirent to human readable string (i.e. file type to string)
//
// parameters:
//      f_type - type of file (as specified in dirent struct)
//
// returns: const char*
//      human readable string corresponding to the given file type information
//
static const char* file_type_str(unsigned char f_type) {
    switch(f_type) {
        case DT_REG:
            return "regular file";
            break;
            
        case DT_DIR:
            return "directory";
            break;
            
        case DT_FIFO:
            return "fifo (named pipe)";
            break;
            
        case DT_LNK:
            return "symbolic link";
            break;
            
        case DT_CHR:
            return "character special device";
            break;
            
        case DT_BLK:
            return "block special device";
            break;
            
        case DT_SOCK:
            return "UNIX domain socket";
            break;
            
        default:
            return "unknown";
    }
}




/* -------- FILE/DIRECTORY FILTERING FUNCTIONS -------- */


// Filter function for scandir(), filters out hidden files and directories
//
// parameters:
//      entry - the directory entry to be tested
//
// returns: int
//      0 if directory entry is hidden, nonzero otherwise
//
static int filter_hidden(const struct dirent* entry) {
    return (entry->d_name[0] == '.') ? 0 : 1;
}

// Filter function for scandir(), filters out only parent and current directory ('.' and '..')
//
// parameters:
//      entry - the directory entry to be tested
//
// returns: int
//      0 if directory entry is parent ('..') or current ('.'), nonzero otherwise
//
static int filter_show_hidden(const struct dirent* entry) {
    return ( strncmp(entry->d_name, ".", 2) == 0 || strncmp(entry->d_name, "..", 3) == 0 ) ? 0 : 1;
}

/* -------- END FILE/DIRECTORY FILTERING FUNCTIONS -------- */






/* -------- BYTE SIZE FORMATTING FUNCTIONS -------- */


// Byte formatting function, converts a number of bytes to a string this identity
// function simply converts to the string representation of the given number
// (i.e. 1024 becomes "1024") as if a call to printf("%lld", num_bytes) was made
//
// parameters:
//      num_bytes - the number to be converted to a string
//
// returns: char*
//      a pointer to a null terminated array of characters representing the string
//      format of 'num_bytes', the caller must free this memory using free() after use
//
static char* byte_format_identity(long long num_bytes) {
    char* ident_str = malloc(20);               // 19 bytes for 19 digit number (2^64 - 1) +1 for null terminator
    snprintf(ident_str, 20, "%lld", num_bytes);
    return ident_str;
}


// Byte formatting function, converts a number of bytes to a string this function converts
// the given number to a human friendly string with a suffix (i.e. B, KB, MB, GB, TB)
// and tenths decimal place if the tenths decimal place is not 0. Note 1000 is used as the
// next order of magnitude and not 1024
//
// examples:
//      1000    ---> "1KB"
//      123     ---> "123B"
//      1144    ---> "1.1KB"
//      1999888 ---> "1.9MB"
//
// parameters:
//      num_bytes - the number to be converted to a human formatted string
//
// returns: char*
//      a pointer to a null terminated array of characters representing the human readable
//      string format of 'num_bytes', the caller must free this memory using free() after use
//
static char* byte_format_human(long long num_bytes) {
    // Lookup table for size suffixes
    static const char* size_suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    
    // Allocate 3 bytes for digits (formatted number always less than 1000)
    // + 2 bytes for decimal point and tenths digit
    // + 2 byte size specifier (i.e. KB, MB, GB) + 1 for null terminator
    char* human_str = malloc(8);
    
    // Continually divide the number of bytes by 1000 until a number <1000 is reached
    unsigned int size_index, remainder;
    for(size_index = 0, remainder = 0; num_bytes >= 1000; size_index++) {
        remainder = num_bytes % 1000;
        num_bytes /= 1000;
    }
    
    // Print the number of bytes followed by a suffix indicating the scale
    // if the remainder is greater than or equal to 100 the tenth's decimal
    // place is printed
    if(remainder < 100) {
        snprintf(human_str, 8, "%lld%s", num_bytes, size_suffixes[size_index]);
    } else {
        snprintf(human_str, 8, "%lld.%d%s", num_bytes, remainder / 100, size_suffixes[size_index]);
    }
    
    return human_str;
}

/* -------- END BYTE SIZE FORMATTING FUNCTIONS -------- */






// Recursive helper function for computer_dir_size(), see below
//
// parameters:
//      dir_path   - the path of the directory to be scanned
//      pdir_sizes - pointer to array of directory sizes
//      dir_index  - pointer to current index into 'pdir_sizes' array
//      array_size - pointer to number of elements 'pdir_sizes' can currently hold (for resizing array)
//
//      dont_store - flag indicating whether or not to store the directory size in the 'pdir_sizes'
//                   array, used by recursive calls to skip storing hidden directory sizes when the
//                   filter function is set to filter hidden entries. 0 indicates this flag is false
//                   1 indicates the flag is true
//
// returns: void
//
static void compute_dir_size_r(const char* dir_path, off_t** pdir_sizes, int* dir_index, int* array_size, int dont_store) {
    int cur_index = *dir_index;
    
    //  The following if block doubles the memory capacity for the pdir_sizes array when
    //  the array is full.
    //
    //  The resizing is done in this way to keep the cost of insertion to O(1) since the
    //  size is not known ahead of time. By doubling the size, each resizing operation,
    //  the number of resizes required tends to 0 as more and more elements are inserted
    //  since the size of the array grows exponentially while the number of elements
    //  being inserted grows linearly (i.e. amortization).
    //
    if(*dir_index >= *array_size) {
        *array_size *= 2;
        *pdir_sizes = realloc(*pdir_sizes, sizeof(off_t) * (*array_size));
    }
    
    // Initialize directory size
    (*pdir_sizes)[cur_index] = 0;
    
    struct dirent** entries;
    int num_entries = scandir(dir_path, &entries, filter_show_hidden, alphasort);
    
    // Check if directory was successfully scanned otherwise exit function
    if(num_entries < 0) {
        return;
    } else if(num_entries == 0) {
        // Directory was successfully scanned but had no entries
        free(entries);
        return;
    }
    
    // Save current directory, this is needed to restore the working directory
    // later, this doesn't need error checking since scandir would not return
    // successful and thus the function would exit before executing this statement
    DIR* dir_save = opendir(".");
    
    // Switch working directory to given directory
    chdir(dir_path);
    
    for(int i=0; i < num_entries; free(entries[i]), i++) {
        struct dirent* current_dirent = entries[i];
        
        // Recursively calculate size of subdirectory
        if(current_dirent->d_type == DT_DIR) {
            
            // Parse subdirectory recursively
            if( (current_dirent->d_name[0] == '.' && filter_function == filter_hidden) || dont_store == 1) {
                
                // If the subdirectory in question is a hidden subdirectory and the filter function specifies
                // that hidden entries should be ignored then we do not want to store the corresponding size
                // in the 'pdir_sizes' array as it is not needed and will mess up the indexing used by
                // parse_directory(). To recursively compute the directory size without storing the sizes in
                // the 'pdir_sizes' array, the 'dont_store' flag is set so resize or index advance operations
                // are not attempted, the subdirectory size will be stored on the stack in 'subdir_size'
                
                int    local_index  = 0;
                off_t* subdir_size  = alloca(sizeof(off_t));    // Alloca is used here since [1] gives a type warning
                
                compute_dir_size_r(current_dirent->d_name, &subdir_size, &local_index, array_size, 1);
                
                // Add subdirectory size to current directory size
                (*pdir_sizes)[cur_index] += *subdir_size;
            } else {
                int r_index = ++(*dir_index);
                compute_dir_size_r(current_dirent->d_name, pdir_sizes, dir_index, array_size, 0);
                
                // Add subdirectory size to current directory size
                (*pdir_sizes)[cur_index] += (*pdir_sizes)[r_index];
            }
            
        } else if(current_dirent->d_type == DT_REG) {
            // Get file size
            struct stat entry_info;
            if(stat(current_dirent->d_name, &entry_info) < 0) {
                // If stat fails skip file
                continue;
            }
            
            // Add file size to current directory size
            (*pdir_sizes)[cur_index] += entry_info.st_size;
        }
    }
    
    // Free memory for dirent array
    free(entries);
    
    // Switch back to working directory before function call
    fchdir(dirfd(dir_save));
    closedir(dir_save);
}


// Recursively traverses the file tree at root 'dir_path' and computes directory sizes
// to be returned in an array
//
// parameters:
//      dir_path  - the path of the directory to be scanned
//
// returns: off_t*
//      An array with directory sizes in bytes. Array order is alphabetical and is same as
//      parse_directory() scan order. First index (index 0) corresponds to the size of the
//      directory pointed to by 'dir_path'. Array must be freed using free()
//
static off_t* compute_dir_size(const char* dir_path) {
    // Initialize array to arbitrary size and zero elements
    off_t* dir_sizes = calloc(sizeof(off_t), 10);
    
    int index = 0;
    int array_size = 10;
    compute_dir_size_r(dir_path, &dir_sizes, &index, &array_size, 0);
    
    return dir_sizes;
}



// Computes md5 checksum of file contents of file at 'path' and places the
// the corresponding checksum as a string of hexadecimal characters into
// the buffer pointed to by 'md5_str' including the null terminator. If
// the buffer size 'n' is less than MD5_DIGEST_LENGTH*2 + 1 = 33 bytes
// then the string is truncated to n-1 characters and null terminated
//
// parameters:
//      path     - the path of the file used to calculate the md5 checksum
//      blk_size - blocksize for efficient filesystem I/O, can be obtained from stat struct field 'st_blksize'
//      md5_str  - pointer to a buffer to hold the md5 checksum hexadecimal string
//      n        - the size of the buffer in bytes
//
// returns: int
//      0 if the md5 checksum was computed successfully, otherwise -1 will be returned.
//      If the error was due to file IO errno will be set appropriately, otherwise the
//      error was caused by the MD5 hashing. Thus errno should be cleared before calling
//      this function.
//
static int fcompute_md5_strn(const char* path, blksize_t blk_size, char* md5_str, unsigned int n) {
    // Open file for binary read
    FILE* fp = fopen(path, "rb");
    
    // Check if file opened successfully, if not return -1 to indicate an error
    if(fp == NULL) {
        return -1;
    }
    
    // Setup md5 context
    MD5_CTX md5_ctx;
    if(MD5_Init(&md5_ctx) == 0) {   // Check for initialization error
        
        // If an error occured close the file and return -1 to indicate error
        fclose(fp);
        return -1;
    }
    
    // Read bytes from the file until either EOF is reached or an error occurs
    unsigned char buffer[blk_size];
    unsigned int bytes_read;
    
    do {
        bytes_read = (unsigned int)fread(buffer, 1, blk_size, fp);
        
        // If a read error occured close the file and return -1 to indicate error
        if(ferror(fp) != 0) {
            fclose(fp);
            return -1;
        }
        
        MD5_Update(&md5_ctx, buffer, bytes_read);
    } while(feof(fp) == 0);
    
    fclose(fp);
    
    // Put md5 hash into 'md5_bytes'
    unsigned char md5_bytes[MD5_DIGEST_LENGTH];
    if(MD5_Final(md5_bytes, &md5_ctx) == 0) {
        // If an error occured return -1 to indicate error
        return -1;
    }
    
    // Convert md5 hash into hex string and place into 'md5_str'
    static const char* hex_table = "0123456789abcdef";
    
    int i;
    for(i=0; i < MD5_DIGEST_LENGTH && i*2 < n-2; i++) {
        // 'hex_table' is used to convert nibbles to hex chars
        // string is written in big-endian so the MSB is written
        // first and he LSB last, as an example the binary string
        // 1001 1010 0001 1111 becomes 9A1F
        (*md5_str++) = hex_table[(md5_bytes[i]>>4) & 0xF];
        (*md5_str++) = hex_table[ md5_bytes[i]     & 0xF];
    }
    
    // If the string was truncated check to see if one more hex digit
    // could fit
    if(i < MD5_DIGEST_LENGTH && i*2 < n-1) {
        (*md5_str++) = hex_table[(md5_bytes[i]>>4) & 0xF];
    }
    
    *md5_str = '\0';    // Append null terminator
    
    return 0;   // return success
}



// Recursive helper function for parse_directory(), see below
//
// parameters:
//      dir_path  - the path of the directory to be scanned
//      dir_sizes - an array of directory sizes
//      dir_index - pointer to current index into 'pdir_sizes' array
//      cur_depth - current number of subdirectories followed (for output indentation)
//
// returns: void
//
static void parse_directory_r(const char* dir_path, off_t* dir_sizes, int* dir_index, int cur_depth) {
    struct dirent** entries;
    int num_entries = scandir(dir_path, &entries, filter_function, alphasort);
    
    // Check if directory was succesfully scanned otherwise print error message
    // and return
    if(num_entries < 0) {
        printf("| %s (directory - error parsing directory: %s)\n", dir_path, strerror(errno));
        return;
    }
    
    // Print directory information (for directories other than the root working directory)
    if(cur_depth >= 1) {
        char* size_str = byte_formatter((long long)dir_sizes[*dir_index]);
        printf("| %s (directory - %s)\n", dir_path, size_str);
        free(size_str);
    }
    
    if(num_entries == 0) {      // Directory was successfully scanned but had no entries
        
        // Print indentation
        if(cur_depth >= 1) {
            char indentation_str[cur_depth*3];
            memset(indentation_str, ' ', cur_depth*3);
            printf("%.*s", cur_depth*3, indentation_str);
        }
        
        printf("*** empty directory ***\n");
        
        free(entries);
        
        return;
    }
    
    // Save current directory, this is needed to restore the working directory
    // later, this doesn't need error checking since scandir would not return
    // successful and thus the function would exit before executing this statement
    DIR* dir_save = opendir(".");
    
    // Switch working directory to given directory
    chdir(dir_path);
    
    for(int i=0; i < num_entries; free(entries[i]), i++) {
        struct dirent* current_dirent = entries[i];
        
        // Handle indentation printing
        if(cur_depth >= 1) {
            char indentation_str[cur_depth*3];
            memset(indentation_str, (current_dirent->d_type == DT_DIR) ? '-' : ' ', cur_depth*3);
            printf("%.*s", cur_depth*3, indentation_str);
        }
        
        if(current_dirent->d_type == DT_DIR) {          // Subdirectories
            
            // Parse subdirectory recursively
            (*dir_index)++;
            parse_directory_r(current_dirent->d_name, dir_sizes, dir_index, cur_depth+1);
        } else if(current_dirent->d_type == DT_REG) {   // Regular files
            
            // Get file size
            struct stat entry_info;
            if(stat(current_dirent->d_name, &entry_info) < 0) {
                // If stat failed then print the name, type of file and an error message
                printf("| %s (%s - error parsing file: %s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type), strerror(errno));
                continue;
            }
            
            // Format byte size
            char* size_str = byte_formatter((long long)entry_info.st_size);
            
            // Compute MD5 checksum of file
            char md5_str[MD5_DIGEST_LENGTH*2 + 1];
            errno = 0;
            
            if(fcompute_md5_strn(current_dirent->d_name, entry_info.st_blksize, md5_str, MD5_DIGEST_LENGTH*2 + 1) == 0) {
                
                // Print file information and md5 checksum
                printf("| %s (%s - %s - %s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type), size_str, md5_str);
                
            } else {
                
                // An error occured while opening/reading the file, in this case the rest
                // of the information on the file will be printed but the md5 checksum
                // will be replaced with an error message
                printf("| %s (%s - %s - error computing md5: %s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type), size_str, (errno == 0) ? "hash error" : strerror(errno));
                
            }
            
            free(size_str);
        } else if(current_dirent->d_type == DT_LNK) {   // Symbolic links
            
            // Determine what the symlink points to, first a buffer is needed to hold the
            // symlink contents, the size of which is determined by a call to lstat()
            struct stat symlink_info;
            if(lstat(current_dirent->d_name, &symlink_info) < 0) {
                // If an error occured while trying to lstat the symlink, an error message
                // will be printed to the user
                printf("| %s (%s - error parsing symlink: %s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type), strerror(errno));
                continue;
            }
            
            // Now the symlink contents can be read
            char symlink_name[symlink_info.st_size+1];
            symlink_name[symlink_info.st_size] = '\0';
            
            ssize_t symlink_size = readlink(current_dirent->d_name, symlink_name, symlink_info.st_size);
            if(symlink_size < 0) {
                // If an error occured while trying to read the symlink, an error message
                // will be printed to the user
                printf("| %s (%s - error reading symlink: %s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type), strerror(errno));
                continue;
            }
            
            
            // Determine the absolute path of the symlink
            char* absolute_path = realpath(current_dirent->d_name, NULL);
            if(absolute_path == NULL) {
                // If an error occured while trying to resolve the absolute path, an error message
                // will be printed to the user
                printf("| %s (%s - error resolving symlink: %s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type), strerror(errno));
                continue;
            }
            
            printf("| %s (%s - points to '%s', absolute path : '%s')\n", current_dirent->d_name, file_type_str(current_dirent->d_type), symlink_name, absolute_path);
            free(absolute_path);
        } else {                                        // Other (i.e. character devices and block devices)
            printf("| %s (%s)\n", current_dirent->d_name, file_type_str(current_dirent->d_type));
        }
    }
    
    // Free memory for dirent array
    free(entries);
    
    // Switch back to working directory before function call
    fchdir(dirfd(dir_save));
    closedir(dir_save);
}


// Recursively traverses the file tree at root 'dir_path' and prints information on
// the child directory entries including name, size, type and md5 checksum
//
// parameters:
//      dir_path  - the path of the directory to be scanned
//
// returns:     void
//
static void parse_directory(const char* dir_path) {
    off_t* dir_sizes = compute_dir_size(dir_path);
    
    int index = 0;
    parse_directory_r(dir_path, dir_sizes, &index, 0);
    
    free(dir_sizes);
}


int main(int argc, const char * argv[]) {
    
    static const char* USAGE_STR = "usage: 'gls [-ah] [directory_name]'";
    
    // Set default options
    filter_function = filter_hidden;
    byte_formatter  = byte_format_identity;
    
    // Check to see if user requested extended usage information
    // by passing '--help' (i.e. help has highest precedence)
    for(int i=1;i<argc;i++) {
        // print usage information and exit the program
        if(strncmp(argv[i], "--help", sizeof("--help")) == 0) {
            printf("gls version %s\n\n", VERSION);
            printf("%s\n", USAGE_STR);
            printf("\ta : show hidden files and directories\n");
            printf("\th : display file sizes in human readable format (i.e. KB, MB, GB)\n");
            
            return 0;
        }
    }
    
    // Parse arguments
    int dir_arg_index = 0;
    for(int i=1;i<argc;i++) {
        
        if(argv[i][0] == '-') {     // Argument contains options
            
            // If the argument contains no options (i.e. just '-') this is invalid,
            // print a message to the user indicating incorrect usage and then print
            // usage information to assist them before exiting the program
            if(argv[i][1] == '\0') {
                fprintf(stderr, "gls: illegal option '-'\n");
                fprintf(stderr, "%s\n", USAGE_STR);
                fprintf(stderr, "Try 'gls --help' for more info\n");
                
                return 1;
            }
            
            // Parse each character in the argument to check if it is a valid option and
            // if so apply that options functionality appropriately
            for(const char* current_arg = argv[i]+1; *current_arg != '\0'; current_arg++) {
                char option = *current_arg;
                
                switch (option) {
                        
                    // If the user specified the '-a' argument then set the filter function
                    // to only filter parent and current directory (i.e. show hidden directories
                    // and files) default is to hide hidden files and directories
                    case 'a':
                        filter_function = filter_show_hidden;
                        break;
                      
                        
                    // If the user specified the '-h' argument then
                    case 'h':
                        byte_formatter = byte_format_human;
                        break;
                        
                        
                    // Invalid option, print a message to the user indicating incorrect usage
                    // and then print usage information to assist them before exiting the program
                    default:
                        fprintf(stderr, "gls: illegal option '-%c'\n", option);
                        fprintf(stderr, "%s\n", USAGE_STR);
                        fprintf(stderr, "Try 'gls --help' for more info\n");
                        
                        return 1;
                }
            }
            
        } else {
            
            // If multiple directory arguments are passed print an error message
            // indicating the ambuiguity and exit the program after printing
            // usage information
            if(dir_arg_index != 0) {
                fprintf(stderr, "gls: Please specify only one directory\n");
                fprintf(stderr, "%s\n", USAGE_STR);
                fprintf(stderr, "Try 'gls --help' for more info\n");
                
                return 2;
            }
            
            // Set directory argument index to potential directory path
            dir_arg_index = i;
            
        }
        
    }
    
    // Check if argument is accessible directory or not, if no directory
    // argument was given then assume user requested information on the
    // current working directory (i.e. '.')
    const char* dir_path = (dir_arg_index != 0) ? argv[dir_arg_index] : ".";
    
    DIR* dir = opendir(dir_path);
    if(dir == NULL) {
        // If there was an error trying to access the specified directory print an
        // error message indicating why and exit the program
        fprintf(stderr, "gls: Error accessing '%s': %s\n", dir_path, strerror(errno));
        
        return 3;
    }
    closedir(dir);
    
    // Traverse and parse given directory
    parse_directory(dir_path);
    
    return 0;
}
