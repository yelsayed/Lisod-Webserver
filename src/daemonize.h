/******************************************************************************
 * Reference: http://www.enderunix.org/docs/eng/daemon.php                    *
 * Modified by: Wolf Richter <wolf@cs.cmu.edu>                                *
 * O_EXCL Bug Fix by: Ming Han <mteh@andrew.cmu.edu                           *
 ******************************************************************************/


/* daemonize includes */
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * internal signal handler
 */
void signal_handler(int sig);

/**
 * internal function daemonizing the process
 */
int daemonize(char* lock_file);