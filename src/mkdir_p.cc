#include <string.h>
#include <limits.h>     /* PATH_MAX */
#include <sys/stat.h>   /* mkdir(2) */
#include <errno.h>
#include <stdlib.h>


/**
  * This function ensures that a directory exists, and comes from the github.
  * https://gist.github.com/JonathonReinhart/8c0d90191c38af2dcadb102c4e202950
  */
int mkdir_p(const char *path, mode_t mode)
{
    /* Adapted from http://stackoverflow.com/a/2336245/119527 */
    const size_t len = strlen(path);
    char _path[PATH_MAX];
    char *p;

    errno = 0;

    /* Copy string so its mutable */
    if (len > sizeof(_path)-1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(_path, path);

    /* Iterate the string */
    for (p = _path + 1; *p; p++) {
        if (*p == '/') {
            /* Temporarily truncate */
            *p = '\0';

            if (mkdir(_path, mode) != 0) {
                if (errno != EEXIST)
                    return -1;
            }

            *p = '/';
        }
    }

    if (mkdir(_path, mode) != 0) {
        if (errno != EEXIST)
            return -1;
    }
    return 0;
}

/**
  * Given a path, ensure that the immediate parent of the file specified by the
  * path exists.  If the path ends in a trailing `/`, it is assumed that we
  * want to ensure this directory exists.
  */
int ensureParents(const char *path, mode_t mode = S_IRWXU) {
    char* dup = strdup(path);
    const size_t len = strlen(dup);
    for (size_t p = len; p > 0; p--) {
        if (dup[p] == '/') {
            dup[p] = '\0';
            break;
        }
    }
    int retVal = mkdir_p(dup, mode);
	free(dup);
	return retVal;
}
