typedef struct pipe_buffer{
 int fd;
 unsigned char *data;
 size_t size;
 size_t written;
} pipe_buffer;

FILE* stream2data(pipe_buffer *buffer, unsigned char* data, size_t size);
FILE* data2stream(unsigned char* data, size_t size);
