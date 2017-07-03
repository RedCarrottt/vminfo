#include "ProcessGroup.h"
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int ProcessGroup::sMaxPss = 0;

ProcessGroup::ProcessGroup(const char* process_name) {
	// If constructor is done, it contains 'Process'es.
	// Each Process has attributes which has already set,
	// and its attributes are "Process Name", "Total",
	// "Text", "Data", and so on.

	// Set the name of the process group
	this->mProcessName = new char[strlen(process_name) + 1];
	memcpy(this->mProcessName, process_name, strlen(process_name) + 1);

	// Set pid list for given process name
	this->setProcesses();
}
ProcessGroup::~ProcessGroup() {
	// Release process name string 
	delete[] this->mProcessName;

	// Release each elements of mProcesses
	std::vector<Process*>::iterator it;
	for(it = this->mProcesses.begin();
			it != this->mProcesses.end();
			it++) {
		delete (*it);
	}
	// Clear entire mProcesses list 
	this->mProcesses.clear();
}
const char* ProcessGroup::getProcessName() {
	return this->mProcessName;
}
void ProcessGroup::getTotalMessage(char* buffer, int bufferSize) {
	if(this->getSize() <= 0) {
		snprintf(buffer, bufferSize, "");
		return;
	}

	int totalText = 0;
	int totalData = 0;
//	int totalBssHeap = 0;
	int totalStack = 0;
	int totalSharedLibrary = 0;
	int totalPss = 0;

	std::vector<Process*>::iterator it;
	for(it = this->mProcesses.begin();
			it != this->mProcesses.end();
			it++) {
		Process* p = (*it);
		totalText += p->getText();
		totalData += p->getData();
//		totalBssHeap += p->getBssHeap();
		totalStack += p->getStack();
		totalSharedLibrary += p->getSharedLibrary();
		totalPss += p->getPss();
		int total = p->getText() + p->getData() + p->getStack() + p->getSharedLibrary();

		// LOGGING
//		printf("%d: %d %d %d %d = %d\n", 
//				p->getPid(), p->getText(), p->getData(), 
//				p->getStack(), p->getSharedLibrary(), total);
	}
	int avgSharedLibrary = totalSharedLibrary / this->getSize();

	struct timeval tv;
	long long timestamp_us;
	gettimeofday(&tv, NULL);
	timestamp_us = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  if(totalPss > sMaxPss)
    sMaxPss = totalPss;

	snprintf(buffer, bufferSize, "%lld %d %d %d %d %d %d",
			timestamp_us, 
			totalText, totalData, totalStack, avgSharedLibrary, totalPss, sMaxPss);
	return;
}

Process& ProcessGroup::getProcess(int index) {
	return *(this->mProcesses[index]);
}
int ProcessGroup::getSize() {
	return this->mProcesses.size();
}
void ProcessGroup::setProcesses() {
	int pd[2];
	int pid_first;
	char* given_pname = this->mProcessName; // given process name
	// make pipe
	if(pipe(pd) == -1) {
		printf("pipe creation failed\n");
	}

	// fork first process
	pid_first = fork();
	if(pid_first < 0) {
		// fork error
		printf("Fork error\n");
		return;
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
				// Add new process snapshot class to the list
				this->mProcesses.push_back(new Process(read_pid));
			}		
		}
		// finish piping
		int status;
		close(pd[0]);
		close(pd[1]);
		waitpid(pid_first, &status, WUNTRACED); // wait for child process
	}
}
