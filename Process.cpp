#include "Process.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

Process::Process(int pid) {
	this->mPid = pid;
	getProcessInfo();
}

int Process::getPid() {
	return this->mPid;
}
int Process::getText() {
	if(this->mInitFailed < 0)
		return -1;
	return this->mTextSegment;
}
int Process::getData() {
	if(this->mInitFailed < 0)
		return -1;
	return this->mDataSegment;
//	return this->mDataStack - this->mStackSegment;
}
//int Process::getBssHeap() {
//	if(this->mInitFailed < 0)
//		return -1;
//	return this->mDataSegment - this->getData();
//}
int Process::getStack() {
	if(this->mInitFailed < 0)
		return -1;
	return this->mStackSegment;
}
int Process::getSharedLibrary() {
	if(this->mInitFailed < 0)
		return -1;
	return this->mSharedLibrary;
}
int Process::getPss() {
	if(this->mInitFailed < 0)
		return -1;
	return this->mPss;
}
void Process::getProcessInfo() {
	FILE *fp;
	char procPath[100];
	int misc;

//	{
//		snprintf(procPath, 100, "/proc/%d/statm", this->mPid);
//		if((fp = fopen(procPath, "r")) == NULL) {
//			goto error;
//		}
//		int dataStackPage = 0;
//		fscanf(fp, "%d %d %d %d %d %d %d", &misc, &misc, &misc, &misc, &misc, &dataStackPage, &misc);
//		this->mDataStack = dataStackPage * 4;
//		fclose(fp);
//	}

	{
		snprintf(procPath, 100, "/proc/%d/status", this->mPid);
		if((fp = fopen(procPath, "r")) == NULL) {
			goto error;
		}

#define EXTRACT_NUMBER(fp, num) fscanf(fp, "%d", &num);

		char buffer[1024];
		while(fscanf(fp, "%s", buffer) != EOF) {
			if(strncmp(buffer, "VmExe:", strlen(buffer)) == 0) {
				EXTRACT_NUMBER(fp, this->mTextSegment);
			} else if(strncmp(buffer, "VmData:", strlen(buffer)) == 0) {
				EXTRACT_NUMBER(fp,  this->mDataSegment);
			} else if(strncmp(buffer, "VmLib:", strlen(buffer)) == 0) {
				EXTRACT_NUMBER(fp,  this->mSharedLibrary);
			} else if(strncmp(buffer, "VmStk:", strlen(buffer)) == 0) {
				EXTRACT_NUMBER(fp,  this->mStackSegment);
			}
		}
		fclose(fp);
		getPssFromSmaps();
	}

success:
	this->mInitFailed = 0;
	return;

error:
	this->mInitFailed = 1;
	return;
}

void Process::getPssFromSmaps() {
	// Open /proc/{pid}/smaps
	FILE* fp;
	char path[1024];
	struct stat stat_buf;
	sprintf(path, "/proc/%d/smaps", this->mPid); // Path of smaps for given pid
	if(getuid() != 0) {
		if(stat(path, &stat_buf) == -1 || (stat_buf.st_uid != getuid()) ) {
			// EXCEPTION this process does not have permission to read the smaps
			this->mInitFailed = 1;
			return;
		}
	}
	fp = fopen(path, "r");
	if(fp == NULL) {
		// EXCEPTION opening the smaps of given pid is failed
		this->mInitFailed = 1;
		return;
	}
	// Read rss & pss from /proc/{pid}/smaps
	char buffer[1024];
	int line_num = 0;
	int total_pss = 0;
	int total_rss = 0;
	int total_private_clean = 0;
	int total_private_dirty = 0;
	while(fgets(buffer, 1024, fp)) {
		const int LINE_PER_OBJECT = 19;
		int line_idx = line_num % LINE_PER_OBJECT;

//    printf("%d: %s \n", line_idx, buffer);
		switch(line_idx) {
			case 0:		// Header : Address, Permissions, Offset, Time, Size, Object Name
				{
					int tok_idx = 0;
					char* tok = strtok(buffer, " ");
					char* read_object_name = NULL;
					while(tok != NULL) {
						switch(tok_idx) {
							case 5:
								// Read object name
								read_object_name = new char[strlen(tok) + 1];
								memcpy(read_object_name, tok, strlen(tok) + 1);
								break;
						}
						tok = strtok(NULL, " ");
						tok_idx++;
					}
					// EXCEPTION If there is not object name for the object, set default object name
          int length = strlen(read_object_name) + 1;
					if(read_object_name == NULL || length <= 2) {
						const char DEFAULT_NAME[] = "anonymous";
						read_object_name = new char[strlen(DEFAULT_NAME) + 1];
						memcpy(read_object_name, DEFAULT_NAME, strlen(DEFAULT_NAME) + 1);
					}
					// HERE Read object name
					// not use for present
          for(int j=0; j<length; j++) {
            if(read_object_name[j] == '\n') read_object_name[j] = ' ';
          }
          //printf("%s ", read_object_name);
				}
				break;
			case 1:		// Size
				break;
			case 2:		// Rss (KB)
				{
					int tok_idx = 0;
					char* tok = strtok(buffer, " ");
					int read_object_rss = -1;
					while(tok != NULL) {
						switch(tok_idx) {
							case 1:
								read_object_rss = atoi(tok);
								// HERE read object rss
								// add its rss to total rss
								total_rss += read_object_rss;
								// TODO set object's rss
								break;
						}
						tok = strtok(NULL, " ");
						tok_idx++;
					}
					// EXCEPTION If there is not object name for the object, set as an error occured
					if(read_object_rss == -1) {
						this->mInitFailed = 1;
						return;
					}
				}
				break;
			case 3:		// Pss (KB)
				{
					int tok_idx = 0;
					char* tok = strtok(buffer, " ");
					int read_object_pss = -1;
					while(tok != NULL) {
						switch(tok_idx) {
							case 1:
								read_object_pss = atoi(tok);
								// HERE read object pss
								// add its pss to total pss
								total_pss += read_object_pss;
								// TODO set object's pss
								break;
						}
						tok = strtok(NULL, " ");
						tok_idx++;
					}
					// EXCEPTION If there is not object name for the object, set as an error occured
					if(read_object_pss == -1) {
						this->mInitFailed = 1;
						return;
					}
          //printf("%d\n", read_object_pss);
				}
				break;
			case 4:		// Shared Clean
				break;
			case 5:		// Shared Dirty
				break;
			case 6:		// Private Clean
				{
					int tok_idx = 0;
					char* tok = strtok(buffer, " ");
					int read_object_private_clean = -1;
					while(tok != NULL) {
						switch(tok_idx) {
							case 1:
								read_object_private_clean = atoi(tok);
								// HERE read object private clean
								// add its priavet clean to total private clean
								total_private_clean += read_object_private_clean;
								// TODO set object's private clean
								break;
						}
						tok = strtok(NULL, " ");
						tok_idx++;
					}
					// EXCEPTION If there is not object name for the object, set as an error occured
					if(read_object_private_clean == -1) {
						this->mInitFailed = 1;
						return;
					}
				}
				break;
			case 7:		// Private Dirty
				{
					int tok_idx = 0;
					char* tok = strtok(buffer, " ");
					int read_object_private_dirty = -1;
					while(tok != NULL) {
						switch(tok_idx) {
							case 1:
								read_object_private_dirty = atoi(tok);
								// HERE read object private dirty
								// add its priavet clean to total private dirty
								total_private_dirty += read_object_private_dirty;
								// TODO set object's private dirty
								break;
						}
						tok = strtok(NULL, " ");
						tok_idx++;
					}
					// EXCEPTION If there is not object name for the object, set as an error occured
					if(read_object_private_dirty == -1) {
						this->mInitFailed = 1;
						return;
					}
				}
				break;
			case 8:		// Referenced
				break;
			case 9:		// Anonymous
				break;
			case 10:	// AnonHughPages
				break;
      case 11:  // Shared Huge TLB
        break;
      case 12:  // Private Huge TLB
        break;
			case 13:	// Swap
				break;
      case 14:  // Swap PSS
        break;
			case 15:	// KernelPageSize
				break;
			case 16:	// MMUPagesSize
				break;
			case 17:	// Locked
				break;
      case 18:  // VM Flags
        break;
		}
		line_num++;
	}
	// set rss & pss of the pid to process snapshot
	this->mPss = total_pss;
	return;
}
