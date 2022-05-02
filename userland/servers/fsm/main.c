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

#include <stdio.h>
#include <chcore/types.h>
#include <chcore/fsm.h>
#include <chcore/tmpfs.h>
#include <chcore/ipc.h>
#include <chcore/internal/raw_syscall.h>
#include <chcore/internal/server_caps.h>
#include <chcore/procm.h>
#include <chcore/fs/defs.h>
#include "mount_info.h"
#include "fsm.h"

extern struct spinlock fsmlock;


extern struct list_head fsm_mount_info_mapping;

/* Mapping a pair of client_badge and fd to a mount_point_info_node struct*/
void fsm_set_mount_info_withfd(u64 client_badge, int client_fd, int fsm_fd,
						struct mount_point_info_node* mount_point_info) {

	struct client_fd_info_node *private_iter;
	for_each_in_list(private_iter, struct client_fd_info_node, node, &fsm_mount_info_mapping) {
		if (private_iter->client_badge == client_badge) {
			private_iter->fsm_fd[client_fd] = fsm_fd;
			private_iter->mount_point_info[client_fd] = mount_point_info;
			return;
		}
	}
	struct client_fd_info_node *n = (struct client_fd_info_node *)malloc(sizeof(struct client_fd_info_node));
	n->client_badge = client_badge;
	int i;
	for (i = 0; i < MAX_SERVER_ENTRY_PER_CLIENT; i++)
		n->mount_point_info[i] = NULL;

	n->fsm_fd[client_fd] = fsm_fd;
	n->mount_point_info[client_fd] = mount_point_info;
	/* Insert node to fsm_server_entry_mapping */
	list_append(&n->node, &fsm_mount_info_mapping);
}


/* Get a mount_point_info_node struct with a pair of client_badge and fd*/
struct mount_point_info_node* fsm_get_mount_info_withfd(u64 client_badge, int client_fd, int *fsm_fd) {
	struct client_fd_info_node *n;
	for_each_in_list(n, struct client_fd_info_node, node, &fsm_mount_info_mapping)
		if (n->client_badge == client_badge) {
			*fsm_fd = n->fsm_fd[client_fd];
			return n->mount_point_info[client_fd];
		}
	return NULL;
}

void strip_path(struct mount_point_info_node *mpinfo, char* path) {
	if(strcmp(mpinfo->path, "/")) {
		char* s = path;
		int i, len_after_strip;
		len_after_strip = strlen(path) - mpinfo->path_len;
		if(len_after_strip == 0) {
			path[0] = '/';
			path[1] = '\0';
		} else {
			for(i = 0; i < len_after_strip; ++i) {
				path[i] = path[i + mpinfo->path_len];
			}
			path[i] = '\0';
		}
	}
}

/* You could add new functions here as you want. */
/* LAB 5 TODO BEGIN */
int fsm_alloc_fd() 
{
	static int cnt = 0;
	return ++cnt;
}

int fsm_open(int fd, const char *path, struct ipc_struct *mounted_fs)
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// open
	ipc_msg = ipc_create_msg(mounted_fs, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_OPEN;
	fr_ptr->open.new_fd = fd;
	strncpy(fr_ptr->open.pathname, path, FS_REQ_PATH_BUF_LEN);

	ret = ipc_call(mounted_fs, ipc_msg);
	ipc_destroy_msg(mounted_fs, ipc_msg);
	return ret;
}

int fsm_close(int fd, struct ipc_struct *mounted_fs)
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// close
	ipc_msg = ipc_create_msg(mounted_fs, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_CLOSE;
	fr_ptr->close.fd = fd;

	ret = ipc_call(mounted_fs, ipc_msg);
	ipc_destroy_msg(mounted_fs, ipc_msg);
	return ret;
}

int fsm_create(const char *path, int mode, struct ipc_struct *mounted_fs)
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// create
	ipc_msg = ipc_create_msg(mounted_fs, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_CREAT;
	fr_ptr->creat.mode = mode;
	strncpy(fr_ptr->creat.pathname, path, FS_REQ_PATH_BUF_LEN);

	ret = ipc_call(mounted_fs, ipc_msg);
	ipc_destroy_msg(mounted_fs, ipc_msg);
	return ret;
}

int fsm_get_file_size(char *path, struct ipc_struct *mounted_fs)
{
	int size;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	ipc_msg = ipc_create_msg(mounted_fs, sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_GET_SIZE;
	strncpy(fr_ptr->getsize.pathname, path, FS_REQ_PATH_BUF_LEN);

	size = ipc_call(mounted_fs, ipc_msg);
	ipc_destroy_msg(mounted_fs, ipc_msg);
	return size;
}

int fsm_get_dents(int fd, void *buf, size_t count, struct ipc_struct *mounted_fs)
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// read dir
	count = MIN(count, FS_BUF_SIZE);
	ipc_msg = ipc_create_msg(mounted_fs, count, 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_GETDENTS64;
	fr_ptr->getdents64.fd = fd;
	fr_ptr->getdents64.count = count;

	ret = ipc_call(mounted_fs, ipc_msg);
	if (ret >= 0) {
		memcpy(buf, ipc_get_msg_data(ipc_msg), ret);
	}
	ipc_destroy_msg(mounted_fs, ipc_msg);
	
	return ret;
}

int fsm_read(int fd, void *buf, size_t count, struct ipc_struct *mounted_fs) 
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// read file
	ipc_msg = ipc_create_msg(mounted_fs, count, 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_READ;
	fr_ptr->read.fd = fd;
	fr_ptr->read.count = count;

	ret = ipc_call(mounted_fs, ipc_msg);
	if (ret >= 0) {
		memcpy(buf, ipc_get_msg_data(ipc_msg), ret);
	}
	ipc_destroy_msg(mounted_fs, ipc_msg);
	
	return ret;
}

int fsm_write(int fd, const void *buf, size_t count, struct ipc_struct *mounted_fs) 
{
	int ret;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

	// write file
	ipc_msg = ipc_create_msg(mounted_fs, count + sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_WRITE;
	fr_ptr->write.fd = fd;
	fr_ptr->write.count = count;
	fr_ptr->write.write_buff_begin = 0;
	memcpy((void *)fr_ptr + sizeof(struct fs_request), buf, count);

	ret = ipc_call(mounted_fs, ipc_msg);
	ipc_destroy_msg(mounted_fs, ipc_msg);
	return ret;
}
/* LAB 5 TODO END */


void fsm_server_dispatch(struct ipc_msg *ipc_msg, u64 client_badge)
{
	int ret, fsm_fd;
	bool ret_with_cap = false;
	struct fs_request *fr;
	fr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	struct mount_point_info_node *mpinfo = NULL;

	/* You could add code here as you want.*/
	/* LAB 5 TODO BEGIN */

	/* LAB 5 TODO END */

	spinlock_lock(&fsmlock);

	switch(fr->req) {
		case FS_REQ_MOUNT:
			ret = fsm_mount_fs(fr->mount.fs_path, fr->mount.mount_path); // path=(device_name), path2=(mount_point)
			break;
		case FS_REQ_UMOUNT:
			ret = fsm_umount_fs(fr->mount.fs_path);
			break;
		case FS_REQ_GET_FS_CAP:
			mpinfo = get_mount_point(fr->getfscap.pathname, strlen(fr->getfscap.pathname));
			strip_path(mpinfo, fr->getfscap.pathname);
			ipc_msg->cap_slot_number = 1;
			ipc_set_msg_cap(ipc_msg, 0, mpinfo->fs_cap);
			ret_with_cap = true;
			break;

		/* LAB 5 TODO BEGIN */
		case FS_REQ_OPEN:
			mpinfo = get_mount_point(fr->open.pathname, strlen(fr->open.pathname));
			strip_path(mpinfo, fr->open.pathname);
			fsm_fd = fsm_alloc_fd();
			ret = fsm_open(fsm_fd, fr->open.pathname, mpinfo->_fs_ipc_struct);
			if (ret >= 0) {
				fsm_set_mount_info_withfd(client_badge, fr->open.new_fd, fsm_fd, mpinfo);
			}
			break;
		
		case FS_REQ_CLOSE:
			mpinfo = fsm_get_mount_info_withfd(client_badge, fr->close.fd, &fsm_fd);
			if (mpinfo == NULL) break;
			ret = fsm_close(fsm_fd, mpinfo->_fs_ipc_struct);
			break;
		
		case FS_REQ_CREAT:
			mpinfo = get_mount_point(fr->creat.pathname, strlen(fr->creat.pathname));
			strip_path(mpinfo, fr->creat.pathname);
			ret = fsm_create(fr->creat.pathname, fr->creat.mode, mpinfo->_fs_ipc_struct);
			break;

		case FS_REQ_GET_SIZE:
			mpinfo = get_mount_point(fr->getsize.pathname, strlen(fr->getsize.pathname));
			strip_path(mpinfo, fr->getsize.pathname);
			ret = fsm_get_file_size(fr->getsize.pathname, mpinfo->_fs_ipc_struct);
			break;
			
		case FS_REQ_GETDENTS64:
			mpinfo = fsm_get_mount_info_withfd(client_badge, fr->getdents64.fd, &fsm_fd);
			ret = fsm_get_dents(fsm_fd, (void *)fr, fr->getdents64.count, mpinfo->_fs_ipc_struct);
			break;

		case FS_REQ_READ:
			mpinfo = fsm_get_mount_info_withfd(client_badge, fr->read.fd, &fsm_fd);
			ret = fsm_read(fsm_fd, (void *)fr, fr->read.count, mpinfo->_fs_ipc_struct);
			break;
			
		case FS_REQ_WRITE:
			mpinfo = fsm_get_mount_info_withfd(client_badge, fr->write.fd, &fsm_fd);
			ret = fsm_write(fsm_fd, (void *)fr + sizeof(struct fs_request), fr->write.count, mpinfo->_fs_ipc_struct);
			break;
		/* LAB 5 TODO END */

		default:
			printf("[Error] Strange FS Server request number %d\n", fr->req);
			ret = -EINVAL;
		break;

	}
	
	spinlock_unlock(&fsmlock);

	if(ret_with_cap) {
		ipc_return_with_cap(ipc_msg, ret);
	} else {
		ipc_return(ipc_msg, ret);
	}
}


int main(int argc, char *argv[])
{

	init_fsm();

	ipc_register_server(fsm_server_dispatch);

	while (1) {
		__chcore_sys_yield();
	}
	return 0;
}
