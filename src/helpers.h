#ifndef SNAKE_HELPERS
#define SNAKE_HELPERS
#include <time.h>

extern int DEBUG_MODE;

#define debug(x...) do { \
if (DEBUG_MODE) fprintf(stderr, "[DEBUG] " x); \
} while(0)

#define fatal(x...) { \
fprintf(stderr, "[-] ERROR: " x); \
exit(1); \
}\

#define output(x...) { \
fprintf(stderr, "[%s] %d %d %s\t", process_username, (int)time(0), process_pid, process_name);\
fprintf(stderr, x);\
}\

#endif
