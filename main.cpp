#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "ProcessGroup.h"
#include <sys/types.h>
#include <sys/wait.h>

#define FLAG_NONE				0
#define FLAG_OP_IMMEDIATE		0
#define FLAG_OP_START			2
#define FLAG_OP_END				3
#define FLAG_OP_MASK			FLAG_OP_IMMEDIATE | FLAG_OP_START | FLAG_OP_END

#define FLAG_DEFAULT			FLAG_OP_IMMEDIATE

#define INTERVAL_TIMER			1

char g_selfProcessName[20] = "vminfo";
char g_defaultString[2] = "";
char *g_targetProcessName = g_defaultString;
char *g_fileName = g_defaultString;

int parseFlags(int argc, char **argv);
void immediatePrintVM(char* processName, char* fileName);
int startTimer(char* targetProcessName, char* fileName);
void endTimer();
int getExistProcessId(char* processName);

void alarmHandler(int sig) {
//	printf("Alarm recall %d\n", INTERVAL_TIMER);
//	printf("%s -> %s\n", g_targetProcessName, g_fileName);
	immediatePrintVM(g_targetProcessName, g_fileName);
	alarm(INTERVAL_TIMER);
}

void helpMsg() {
	printf("VMINFO : \n");
	printf("\tvminfo [process name] [file name] -i\n");
	printf("\t\t Immediate Mode (Default)\n");
	printf("\tvminfo [process name] [file name] -s\n");
	printf("\t\t Timer Mode Start (Default)\n");
	printf("\tvminfo -e\n");
	printf("\t\t Timer Mode End (Default)\n");
	printf("\tResult to be printed:\n");
	printf("\t\t[Code Segment Size] [Data Segment Size] [Stack Size] [Shared Library Size] [PSS]\n");
}

int main(int argc, char **argv) {
	// check argument number
	int flag = parseFlags(argc, argv);

	char* targetProcessName = argv[1]; // given process name
	char* fileName = argv[2];
	switch(flag) {
	case FLAG_OP_IMMEDIATE:
		if(argc < 3) {
			helpMsg();
			return -1;
		}
		immediatePrintVM(targetProcessName, fileName);
		break;
	case FLAG_OP_START:
		if(argc < 3) {
			helpMsg();
			return -1;
		}
		return startTimer(targetProcessName, fileName);
		break;
	case FLAG_OP_END:
		endTimer();
		break;
	default:
		printf("Wrong flags\n");
		break;
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
		printf("VMInfo begin : (Interval : %ds)\n", INTERVAL_TIMER);
		alarmHandler(SIGALRM);
		while(1) {
//			printf("VMInfo call\n");
			signal(SIGALRM, alarmHandler);
			alarm(INTERVAL_TIMER);
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
