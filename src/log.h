#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/fcntl.h>

/* init_log
 *  Initiates the global log that is used by server to print while
 *  it's daemonized. This needs a path from the global state of the server
 *
 *  Parameters:
 *      path - path containing the log file
 */
void init_log(const char *path);

/* string_log
 *  Logs the string in the log file and in stdout if the process
 *  is not daemonized. This works with variable inputs. Requires
 *  the log to be initiated.
 *
 *  Parameters:
 *      out    - indicates if the user wanted to print to stdout or stderr
 *      format - string buffer to be printed to log. Can be variable inputs
 */
void string_log(int out, const char *format, ...);

/* close_log
 *  Closes the log safely, should be called whenever server is
 *  shutting down for whatever reason.
 */
void close_log();