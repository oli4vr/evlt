#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include "pipes.h"

void* writer_thread(void* arg) {
 pipe_buffer *buffer = (pipe_buffer*)arg;
 ssize_t bytes_read;
 if (buffer==NULL) {return NULL;}
 while ((bytes_read = read(buffer->fd, buffer->data + buffer->written, buffer->size - buffer->written)) > 0) {
  buffer->written += bytes_read;
  if (buffer->written >= buffer->size) {
   break;
  }
 }
 close(buffer->fd);
 return NULL;
}

FILE* stream2data(pipe_buffer *buffer, unsigned char* data, size_t size) {
 int pipefd[2];

 if (buffer==NULL || data==NULL || size==0) {
  return NULL;
 }

 if (pipe(pipefd) == -1) {
  perror("pipe");
  return NULL;
 }

 buffer->fd = pipefd[0];
 buffer->data = data;
 buffer->size = size;
 buffer->written = 0;

 pthread_t tid;
 if (pthread_create(&tid, NULL, writer_thread, buffer) != 0) {
  perror("pthread_create");
  close(pipefd[0]);
  close(pipefd[1]);
  return NULL;
 }

 FILE *stream = fdopen(pipefd[1], "w");
 if (!stream) {
  perror("fdopen");
  close(pipefd[0]);
  close(pipefd[1]);
  return NULL;
 }

 pthread_detach(tid);

 return stream;
}


FILE* data2stream(unsigned char* data, size_t size) {
 int pipefd[2];
 if (pipe(pipefd) == -1) {
  perror("pipe");
  return NULL;
 }

 ssize_t written = write(pipefd[1], data, size);
 if (written == -1) {
  perror("write");
  close(pipefd[0]);
  close(pipefd[1]);
  return NULL;
 } else if (written != size) {
  fprintf(stderr, "Incomplete write to pipe\n");
  close(pipefd[0]);
  close(pipefd[1]);
  return NULL;
 }

 close(pipefd[1]); // Close the write-end of the pipe, we're done writing

 FILE* stream = fdopen(pipefd[0], "r");
 if (stream == NULL) {
  perror("fdopen");
  close(pipefd[0]);
  return NULL;
 }

 return stream;
}
