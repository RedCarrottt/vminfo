#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "ProcessGroup.h"
#include <sys/types.h>
#include <sys/wait.h>

#define FLAG_NONE				0
#define FLAG_OP_IMMEDIATE		1
#define FLAG_OP_START			2
#define FLAG_OP_END				3
#define FLAG_OP_MASK			FLAG_OP_IMMEDIATE | FLAG_OP_START | FLAG_OP_END

#define FLAG_DEFAULT			FLAG_NONE

#define DEFAULT_INTERVAL_TIMER_SEC			1

char g_selfProcessName[20] = "vminfo";
char g_defaultString[2] = "";
char *g_targetProcessName = g_defaultString;
char *g_fileName = g_defaultString;
int g_interval_timer_sec = DEFAULT_INTERVAL_TIMER_SEC;

int parseFlags(int argc, char **argv);
void immediatePrintVM(char* processName, char* fileName);
int startTimer(char* targetProcessName, char* fileName);
void endTimer();
int getExistProcessId(char* processName);

bool checkRootUser() {
  return ((int)getuid() == 0) ? true : false;
}

void alarmHandler(int sig) {
  immediatePrintVM(g_targetProcessName, g_fileName);
  alarm(g_interval_timer_sec);
}

void helpMsg() {
  printf("VMInfo usage:\n");
  printf("  Inmmediate Mode: vminfo [process name] [file name] -i\n");
  printf("  Timer Mode\n");
  printf("    Start: vminfo [process name] [file name] (interval(sec)) -s\n");
  printf("    End: vminfo -e\n");
  printf("Result (1 Page = 4KB):\n");
  printf("  [Timestamp(us)] [Code Segment Size(Pages)] [Data Segment Size(Pages)] [Stack Size(Pages)] [Shared Library Size(Pages)] [PSS(Pages)]\n");
}

int main(int argc, char **argv) {
  // check argument number
  int flag = parseFlags(argc, argv);

  char* targetProcessName = argv[1]; // given process name
  char* fileName = argv[2];

  switch(flag) {
    case FLAG_OP_IMMEDIATE:
      {
        if(checkRootUser() == false) {
          printf("You should run on root user.\n");
          return -2;
        } else if(argc < 4) {
          helpMsg();
          return -1;
        }
        immediatePrintVM(targetProcessName, fileName);
        break;
      }
    case FLAG_OP_START:
      {
        if(checkRootUser() == false) {
          printf("You should run on root user.\n");
          return -2;
        } else if(argc < 4) {
          helpMsg();
          return -1;
        } else if(argc >= 5) {
          g_interval_timer_sec = atoi(argv[3]);
        }
        return startTimer(targetProcessName, fileName);
        break;
      }
    case FLAG_OP_END:
      {
        if(checkRootUser() == false) {
          printf("You should run on root user.\n");
          return -2;
        }
        endTimer();
        break;
      }
    default:
      {
        helpMsg();
        break;
      }
  }
  return 0;
}

int parseFlags(int argc, char **argv) {
  int flag = FLAG_DEFAULT;
  for(int i=1; i<argc; i++) {
    if(argv[i][0] != '-') {
      continue;
    }
    // Flag detected
    char* flagContents = argv[i];
    // Determining Flags
    while(*flagContents != '\0') {
      switch(*flagContents) {
        case 'i': // Immediate
          flag |= FLAG_OP_IMMEDIATE;
          break;
        case 's': // Start
          flag |= FLAG_OP_START;
          break;
        case 'e': // end
          flag |= FLAG_OP_END;
          break;
        default:
          break;
      }
      flagContents++;
    }
  }
  return flag;
}

void immediatePrintVM(char* processName, char* fileName) {
  ProcessGroup* processGroup = new ProcessGroup(processName);
  char buffer[1024];
  processGroup->getTotalMessage(buffer, 1024);
  FILE* fp;
  if((fp = fopen(fileName, "a")) == NULL) {
    delete processGroup;
    return;
  }
  fprintf(fp, "%s\n", buffer);
  fclose(fp);

  delete processGroup;
  return;
}

int startTimer(char* targetProcessName, char* fileName) {
  // if already timer process exists, it cannot start VMInfo.
  if(getExistProcessId(g_selfProcessName) != 0) {
    printf("VMInfo: already running\n");
    return -1;
  }
  pid_t pid = fork();
  if(pid < 0) {
    // fork error
    printf("VMInfo: fork error\n");
    return -2;
  } else if(pid == 0) {
    // child process
    g_targetProcessName = targetProcessName;
    g_fileName = fileName;
    printf("VMInfo begin : (Interval : %ds)\n", g_interval_timer_sec);
    alarmHandler(SIGALRM);
    while(1) {
      signal(SIGALRM, alarmHandler);
      alarm(g_interval_timer_sec);
      pause();
    }
  }
  return 0;
}
void endTimer() {
  int existPid = getExistProcessId(g_selfProcessName);
  if(existPid != 0) {
    kill(existPid, SIGKILL);
    printf("VMInfo end\n");	
  }
}

int getExistProcessId(char* processName) {
  int existPid = 0;
  int selfPid = (int)getpid();
  int pd[2];
  int pid_first;
  char *given_pname = processName; // given process name
  // make pipe
  if(pipe(pd) == -1) {
    printf("pipe creation failed\n");
  }

  // fork first process
  pid_first = fork();
  if(pid_first < 0) {
    // fork error
    printf("Fork error\n");
    return 0;
  } else if(pid_first == 0) {
    int result;
    // child process
    dup2(pd[1], 1);
    close(pd[0]);
    close(pd[1]);
    // execute "ps -A"
    result = execlp("ps", "ps", "-A", NULL);
    if(result == -1) {
      printf("Command exec error\n");
    }
    exit(127);
  } else {
    // mother process
    dup2(pd[0], 0);
    close(pd[0]);
    close(pd[1]);
    // read the result of "ps -A"
    char buffer[1024];
    int linenum = 0;
    while(gets(buffer)) {
      linenum++;
      if(linenum == 1) continue; // skip first line

      int read_pid = -1;
      char read_pname[1024];

      int index = 0;
      char* ptok = strtok(buffer, " ");
      while(ptok != NULL){
        switch(index) {
          case 0:
            read_pid = atoi(ptok);
            break;
          case 3:
            memcpy(read_pname, ptok, strlen(ptok) + 1);
            break;
        }
        index++;
        ptok = strtok(NULL, " ");
      }
      if(read_pid == -1)
        continue;
      // Read PID & Process Name is here
      if(strncmp(read_pname, given_pname, strlen(given_pname)) == 0
          && strlen(read_pname) == strlen(given_pname)) {
        if(read_pid != selfPid)
          existPid = read_pid;
      }		
    }
    // finish piping
    int status;
    close(pd[0]);
    close(pd[1]);
    waitpid(pid_first, &status, WUNTRACED); // wait for child process

    return existPid;
  }
}
