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

#include <chcore/fsm.h>
#include <chcore/ipc.h>
#include <chcore/assert.h>
#include <chcore/internal/server_caps.h>
#include <chcore/fs/defs.h>
#include <string.h>

static struct ipc_struct * fsm_ipc_struct = NULL;
static struct list_head fs_cap_infos;

struct fs_cap_info_node {
	int fs_cap;
	ipc_struct_t *fs_ipc_struct;
	struct list_head node;
};

struct fs_cap_info_node *set_fs_cap_info(int fs_cap)
{
        struct fs_cap_info_node *n;
        n = (struct fs_cap_info_node *)malloc(sizeof(*n));
        chcore_assert(n);
        n->fs_ipc_struct = ipc_register_client(fs_cap);
        chcore_assert(n->fs_ipc_struct);
        list_add(&n->node, &fs_cap_infos);
        return n;
}

/* Search for the fs whose capability is `fs_cap`.*/
struct fs_cap_info_node *get_fs_cap_info(int fs_cap)
{
        struct fs_cap_info_node *iter;
        struct fs_cap_info_node *matched_fs = NULL;
        for_each_in_list(iter, struct fs_cap_info_node, node, &fs_cap_infos) {
                if(iter->fs_cap == fs_cap) {
                        matched_fs = iter;
                        break;
                }	
        }
        if(!matched_fs) {
                return set_fs_cap_info(fs_cap);
        }
        return matched_fs;
}


static void connect_fsm_server(void)
{
	init_list_head(&fs_cap_infos);
        int fsm_cap = __chcore_get_fsm_cap();
        chcore_assert(fsm_cap >= 0);
        fsm_ipc_struct = ipc_register_client(fsm_cap);
        chcore_assert(fsm_ipc_struct);
}

int fsm_creat_file(char* path) 
{
        if (!fsm_ipc_struct) {
                connect_fsm_server();
        }
        struct ipc_msg *ipc_msg = ipc_create_msg(
                fsm_ipc_struct, sizeof(struct fs_request), 0);
        chcore_assert(ipc_msg);
        struct fs_request * fr =
                (struct fs_request *)ipc_get_msg_data(ipc_msg);
        fr->req = FS_REQ_CREAT;
        strcpy(fr->creat.pathname, path);
        int ret = ipc_call(fsm_ipc_struct, ipc_msg);
        ipc_destroy_msg(fsm_ipc_struct, ipc_msg);
        return ret;
}


int get_file_size_from_fsm(char* path) {
        if (!fsm_ipc_struct) {
                connect_fsm_server();
        }
        struct ipc_msg *ipc_msg = ipc_create_msg(
                fsm_ipc_struct, sizeof(struct fs_request), 0);
        chcore_assert(ipc_msg);
        struct fs_request * fr =
                (struct fs_request *)ipc_get_msg_data(ipc_msg);

        fr->req = FS_REQ_GET_SIZE;
        strcpy(fr->getsize.pathname, path);

        int ret = ipc_call(fsm_ipc_struct, ipc_msg);
        ipc_destroy_msg(fsm_ipc_struct, ipc_msg);
        return ret;
}

static int alloc_fd() 
{
	static int cnt = 0;
	return ++cnt;
}

static int fsm_get_fs_cap(const char *path, char *stripped_path)
{
        if (!fsm_ipc_struct) {
                connect_fsm_server();
        }
        struct ipc_msg *ipc_msg = ipc_create_msg(
                fsm_ipc_struct, sizeof(struct fs_request), 0);
        chcore_assert(ipc_msg);
        struct fs_request * fr =
                (struct fs_request *)ipc_get_msg_data(ipc_msg);

        fr->req = FS_REQ_GET_FS_CAP;
        strcpy(fr->getfscap.pathname, path);

        int ret = ipc_call(fsm_ipc_struct, ipc_msg);
        if (ret >= 0) {
                strcpy(stripped_path, fr->getfscap.pathname);
                ret = ipc_get_msg_cap(ipc_msg, 0);
        }
        ipc_destroy_msg(fsm_ipc_struct, ipc_msg);
        return ret;
}

/* Write buf into the file at `path`. */
int fsm_write_file(const char* path, char* buf, unsigned long size) {
        if (!fsm_ipc_struct) {
                connect_fsm_server();
        }
        int ret = 0;

        /* LAB 5 TODO BEGIN */
        int fs_cap, fd;
        struct fs_cap_info_node *fs_cap_info;
        char stripped_path[FS_REQ_PATH_BUF_LEN];

        unsigned long to_write, offset = 0;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

        // get fs capability
        fs_cap = fsm_get_fs_cap(path, stripped_path);
        if (fs_cap < 0) return fs_cap;
        fs_cap_info = get_fs_cap_info(fs_cap);

        // open file
        fd = alloc_fd();
	ipc_msg = ipc_create_msg(fs_cap_info->fs_ipc_struct,
                sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_OPEN;
	fr_ptr->open.new_fd = fd;
	strncpy(fr_ptr->open.pathname, stripped_path, FS_REQ_PATH_BUF_LEN);
	ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);

	if (ret < 0) {
		// create file
		fr_ptr->req = FS_REQ_CREAT;
		fr_ptr->creat.mode = 0;
		strncpy(fr_ptr->creat.pathname,
                        stripped_path, FS_REQ_PATH_BUF_LEN);
		ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
		if (ret < 0) {
	                ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
                        return ret;
                }
		
		// retry open
		fr_ptr->req = FS_REQ_OPEN;
		fr_ptr->open.new_fd = fd;
		strncpy(fr_ptr->open.pathname,
                        stripped_path, FS_REQ_PATH_BUF_LEN);
		ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
		if (ret < 0) {
	                ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
                        return ret;
                }
	}

	ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);

        // write file
	ipc_msg = ipc_create_msg(fs_cap_info->fs_ipc_struct,
                IPC_SHM_AVAILABLE, 0);
	while (offset < size) {
		to_write = size - offset;
		to_write = to_write < FS_BUF_SIZE ? to_write : FS_BUF_SIZE;
		
		fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
		fr_ptr->req = FS_REQ_WRITE;
		fr_ptr->write.fd = fd;
		fr_ptr->write.count = to_write;
		fr_ptr->write.write_buff_begin = 0;
		memcpy((void *)fr_ptr + sizeof(struct fs_request),
                        buf + offset, to_write);

		ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
		if (ret < 0) {
			ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
			return ret;
		}
		offset += ret;
		if (ret < to_write) break;
	}
	ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);

        // close file
        ipc_msg = ipc_create_msg(fs_cap_info->fs_ipc_struct,
                sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_CLOSE;
	fr_ptr->close.fd = fd;

	ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
	ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
	if (ret < 0) return ret;
        /* LAB 5 TODO END */

        return offset;
}

/* Read content from the file at `path`. */
int fsm_read_file(const char* path, char* buf, unsigned long size) {

        if (!fsm_ipc_struct) {
                connect_fsm_server();
        }
        int ret = 0;

        /* LAB 5 TODO BEGIN */
        int fs_cap, fd;
        struct fs_cap_info_node *fs_cap_info;
        char stripped_path[FS_REQ_PATH_BUF_LEN];

        unsigned long to_read, offset = 0;
	ipc_msg_t *ipc_msg;
	struct fs_request *fr_ptr;

        // get fs capability
        fs_cap = fsm_get_fs_cap(path, stripped_path);
        if (fs_cap < 0) return fs_cap;
        fs_cap_info = get_fs_cap_info(fs_cap);

        // open file
        fd = alloc_fd();
	ipc_msg = ipc_create_msg(fs_cap_info->fs_ipc_struct,
                sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_OPEN;
	fr_ptr->open.new_fd = fd;
	strncpy(fr_ptr->open.pathname, stripped_path, FS_REQ_PATH_BUF_LEN);
	ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);

	if (ret < 0) {
		// create file
		fr_ptr->req = FS_REQ_CREAT;
		fr_ptr->creat.mode = 0;
		strncpy(fr_ptr->creat.pathname,
                        stripped_path, FS_REQ_PATH_BUF_LEN);
		ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
		if (ret < 0) {
	                ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
                        return ret;
                }
		
		// retry open
		fr_ptr->req = FS_REQ_OPEN;
		fr_ptr->open.new_fd = fd;
		strncpy(fr_ptr->open.pathname,
                        stripped_path, FS_REQ_PATH_BUF_LEN);
		ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
		if (ret < 0) {
	                ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
                        return ret;
                }
	}

	ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);

        // read file
	ipc_msg = ipc_create_msg(fs_cap_info->fs_ipc_struct, FS_BUF_SIZE, 0);
	while (offset < size) {
		to_read = size - offset;
		to_read = to_read < FS_BUF_SIZE ? to_read : FS_BUF_SIZE;

		fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
		fr_ptr->req = FS_REQ_READ;
		fr_ptr->read.fd = fd;
		fr_ptr->read.count = to_read;

		ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
		if (ret < 0) {
			ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
			return ret;
		}
		memcpy(buf + offset, ipc_get_msg_data(ipc_msg), ret);
		offset += ret;
		if (ret < to_read) break;
	}
	ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);

        // close file
        ipc_msg = ipc_create_msg(fs_cap_info->fs_ipc_struct,
                sizeof(struct fs_request), 0);
	fr_ptr = (struct fs_request *)ipc_get_msg_data(ipc_msg);
	fr_ptr->req = FS_REQ_CLOSE;
	fr_ptr->close.fd = fd;

	ret = ipc_call(fs_cap_info->fs_ipc_struct, ipc_msg);
	ipc_destroy_msg(fs_cap_info->fs_ipc_struct, ipc_msg);
	if (ret < 0) return ret;
        /* LAB 5 TODO END */

        return offset;
}

void chcore_fsm_test()
{
        if (!fsm_ipc_struct) {
                connect_fsm_server();
        }
        char wbuf[257];
        char rbuf[257];
        memset(rbuf, 0, sizeof(rbuf));
        memset(wbuf, 'x', sizeof(wbuf));
        wbuf[256] = '\0';
        fsm_creat_file("/fakefs/fsmtest.txt");
        fsm_write_file("/fakefs/fsmtest.txt", wbuf, sizeof(wbuf));
        fsm_read_file("/fakefs/fsmtest.txt", rbuf, sizeof(rbuf));
        int res = memcmp(wbuf, rbuf, strlen(wbuf));
        if(res == 0) {
                printf("chcore fsm bypass test pass\n");
        }

}
