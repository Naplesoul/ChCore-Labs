/*
 * Copyright (c) 2022 Institute of Parallel And Distributed Systems (IPADS)
 * ChCore-Lab is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 */

#include "lab5_stdio.h"


extern struct ipc_struct *tmpfs_ipc_struct;

/* You could add new functions or include headers here.*/
/* LAB 5 TODO BEGIN */
int atoi(const char *num);
int vsscanf(char *in, const char *fmt, va_list va);

int alloc_fd() 
{
	static int cnt = 0;
	return ++cnt;
}

int open(char *path)
{
	int ret, fd;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// open
	fd = alloc_fd();
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_OPEN;
	fr_ptr->open.new_fd = fd;
	strncpy(fr_ptr->open.pathname, path, FS_REQ_PATH_BUF_LEN);
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

	if (ret < 0) {
		// create file
		fr_ptr->req = FS_REQ_CREAT;
		fr_ptr->creat.mode = 0;
		strncpy(fr_ptr->creat.pathname, path, FS_REQ_PATH_BUF_LEN);
		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
		if (ret < 0) goto error;
		
		// retry open
		fr_ptr->req = FS_REQ_OPEN;
		fr_ptr->open.new_fd = fd;
		strncpy(fr_ptr->open.pathname, path, FS_REQ_PATH_BUF_LEN);
		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
		if (ret < 0) goto error;
	}

	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	return fd;

error:
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	return ret;
}

int close(int fd)
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// close
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_CLOSE;
	fr_ptr->close.fd = fd;

	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	return ret;
}

int get_file_size(char *path)
{
	int size;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_GET_SIZE;
	strncpy(fr_ptr->getsize.pathname, path, FS_REQ_PATH_BUF_LEN);

	size = ipc_call(tmpfs_ipc_struct, ipc_msg);
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	return size;
}

ssize_t read(int fd, void *buf, size_t n) 
{
	int ret;
	size_t to_read, offset = 0;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// read file
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, FS_BUF_SIZE, 0);
	while (offset < n) {
		to_read = n - offset;
		to_read = to_read < FS_BUF_SIZE ? to_read : FS_BUF_SIZE;

		fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
		fr_ptr->req = FS_REQ_READ;
		fr_ptr->read.fd = fd;
		fr_ptr->read.count = to_read;

		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
		if (ret < 0) {
			ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
			return ret;
		}
		memcpy(buf + offset, ipc_get_msg_data(ipc_msg), ret);
		offset += ret;
		if (ret < to_read) break;
	}
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	return offset;
}

ssize_t write(int fd, const void *buf, size_t n) 
{
	int ret;
	size_t to_write, offset = 0;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// write file
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, IPC_SHM_AVAILABLE, 0);
	while (offset < n) {
		to_write = n - offset;
		to_write = to_write < FS_BUF_SIZE ? to_write : FS_BUF_SIZE;
		
		fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
		fr_ptr->req = FS_REQ_WRITE;
		fr_ptr->write.fd = fd;
		fr_ptr->write.count = to_write;
		fr_ptr->write.write_buff_begin = 0;
		memcpy((void *)fr_ptr + sizeof(struct fs_request), buf + offset, to_write);

		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
		if (ret < 0) {
			ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
			return ret;
		}
		offset += ret;
		if (ret < to_write) break;
	}
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	return offset;
}
/* LAB 5 TODO END */


FILE *fopen(const char * filename, const char * mode) {

	/* LAB 5 TODO BEGIN */
	int fd;
	FILE *file;
	
	fd = open(filename);
	if (fd < 0) return NULL;

	file = (FILE *)malloc(sizeof(FILE));
	file->fd = fd;
	strcpy(file->mode, mode);
	/* LAB 5 TODO END */
    return file;
}

size_t fwrite(const void * src, size_t size, size_t nmemb, FILE * f) {

	/* LAB 5 TODO BEGIN */
	return write(f->fd, src, size * nmemb);
	/* LAB 5 TODO END */
}

size_t fread(void * destv, size_t size, size_t nmemb, FILE * f) {

	/* LAB 5 TODO BEGIN */
	return read(f->fd, destv, size * nmemb);
	/* LAB 5 TODO END */
}

int fclose(FILE *f) {

	/* LAB 5 TODO BEGIN */
	int ret;

	ret = close(f->fd);
	if (ret < 0) return ret;

	free(f);
	/* LAB 5 TODO END */
    return 0;

}

/* Need to support %s and %d. */
int fscanf(FILE * f, const char * fmt, ...) {

	/* LAB 5 TODO BEGIN */
	va_list va;
	char buf[FS_BUF_SIZE];
	char *buf_ptr = buf;
    int res, ret;

	ret = read(f->fd, buf, FS_BUF_SIZE);
	if (ret < 0) return ret;

    va_start(va, fmt);
    res = vsscanf(buf, fmt, va);
    va_end(va);
    
	/* LAB 5 TODO END */
    return res;
}

/* Need to support %s and %d. */
int fprintf(FILE * f, const char * fmt, ...) {

	/* LAB 5 TODO BEGIN */
	va_list va;
	char buf[FS_BUF_SIZE];
	char *buf_ptr = buf;
    int res, ret;

    va_start(va, fmt);
    res = vsprintf(&buf_ptr, fmt, va);
    va_end(va);

	if (res <= 0) return res;
    
	ret = write(f->fd, buf, res);
	/* LAB 5 TODO END */
    return ret;
}

int atoi(const char *num)
{
	int r = 0;
	while (*num > '0' && *num < '9') {
		r = r * 10 + *num - '0';
		++num;
	}
	return r;
}

int vsscanf(char *in, const char *fmt, va_list ap)
{
	union {
		char *c;
		char *s;
		int *i;
		unsigned int *u;
		long *li;
		unsigned long *lu;
		long long *lli;
		unsigned long long *llu;
		short *hi;
		unsigned short *hu;
		signed char *hhi;
		unsigned char *hhu;
		void **p;
	} u;

	for (; *fmt != 0; ++fmt) {
		if (*fmt == '%') {
			++fmt;
			if (*fmt == '\0') break;
			switch (*fmt)
			{
			case 's':
				u.s = va_arg(ap, char*);
				while (*in != 0 && *in != ' ') {
					*(u.s++) = *(in++);
				}
				break;
			
			case 'd':
				u.i = va_arg(ap, int*);
				*u.i = atoi(in);
				while (*in && *in < '9' && *in > '0')
					++in;
				break;
			default:
				break;
			}
		} else if (*fmt == *in) {
			++in;
		}
	}
	return 0;
}