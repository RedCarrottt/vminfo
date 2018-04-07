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
}
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
    int expected_header = 1;

    if(expected_header == 1) {
      // Header : Address, Permissions, Offset, Time, Size, Object Name
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
      if(read_object_name == NULL || strlen(read_object_name) <= 1) {
        const char DEFAULT_NAME[] = "anonymous";
        read_object_name = new char[strlen(DEFAULT_NAME) + 1];
        memcpy(read_object_name, DEFAULT_NAME, strlen(DEFAULT_NAME) + 1);
      }
      // HERE Read object name
      // not use for present
      for(int j=0; j<strlen(read_object_name); j++) {
        if(read_object_name[j] == '\n') read_object_name[j] = ' ';
      }
      expected_header = 0;
      continue;
    } else {
      char* tok = strtok(buffer, " ");
      int tok_idx = 0;
      while(tok != NULL) {
        if(tok_idx == 0) {
          char* title = tok;
          if(strncmp(title, "Rss", 3) == 0) {
            // Rss (KB)
            tok = strtok(NULL, " "); tok_idx++;
            total_rss += atoi(tok);
            break;
          } else if(strncmp(title, "Pss", 3) == 0) {
            // Pss (KB)
            tok = strtok(NULL, " "); tok_idx++;
            total_pss += atoi(tok);
            break;
          } else if(strncmp(title, "Private_Clean", 13) == 0) {
            // Private_Clean (KB)
            tok = strtok(NULL, " "); tok_idx++;
            total_private_clean += atoi(tok);
            break;
          } else if(strncmp(title, "Private_Dirty", 13) == 0) {
            // Private_Dirty (KB)
            tok = strtok(NULL, " "); tok_idx++;
            total_private_dirty += atoi(tok);
            break;
          }
        }
        tok = strtok(NULL, " ");
        tok_idx++;
      }
    }
  }
  // set rss & pss of the pid to process snapshot
  this->mPss = total_pss;
  return;
}
