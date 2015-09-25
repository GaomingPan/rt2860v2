/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

    Module Name:
    rt_proc.c

    Abstract:
    Create and register proc file system for ralink device

    Revision History:
    Who         When            What
    --------    ----------      ----------------------------------------------
*/

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "rt_config.h"

int wl_proc_init(void);
int wl_proc_exit(void);

#ifdef CONFIG_RALINK_RT2880
#define PROCREG_DIR             "rt2880"
#endif /* CONFIG_RALINK_RT2880 */

#ifdef CONFIG_RALINK_RT3052
#define PROCREG_DIR             "rt3052"
#endif /* CONFIG_RALINK_RT3052 */

#ifdef CONFIG_RALINK_RT2883
#define PROCREG_DIR             "rt2883"
#endif /* CONFIG_RALINK_RT2883 */

#ifdef CONFIG_RALINK_RT3883
#define PROCREG_DIR             "rt3883"
#endif /* CONFIG_RALINK_RT3883 */

#ifdef CONFIG_RALINK_RT5350
#define PROCREG_DIR             "rt5350"
#endif /* CONFIG_RALINK_RT5350 */

#ifndef PROCREG_DIR
#define PROCREG_DIR             "rt2880"
#endif /* PROCREG_DIR */

#ifdef CONFIG_PROC_FS
#define MAX_MACLIST_LENGTH  1024
#define PROCREG_DIR "procofmac"

//extern struct proc_dir_entry *procRegDir;
static struct proc_dir_entry *procRegDir;
struct proc_dir_entry *procRegDir2860;

static struct proc_dir_entry *entry_wl_beacon_mac;
static char *maclistbuffer;
static int mac_index;
static int mac_next;
int ProbeRssi;
UCHAR GLOBAL_AddrLocalNum = 0;
UCHAR GLOBAL_AddrLocal[MAX_MCAST_LIST_SIZE][6];
UCHAR GLOBAL_AddrLocalNum1 = 0;
UCHAR GLOBAL_AddrLocal1[MAX_MCAST_LIST_SIZE][6];

static int maclist_proc_show(struct seq_file *m, void *v)
{
	int index = 0;
	seq_printf(m,"[%d] %02x:%02x:%02x:%02x:%02x:%02x\n", 
        ProbeRssi,
		GLOBAL_AddrLocal[index][0],
		GLOBAL_AddrLocal[index][1],
		GLOBAL_AddrLocal[index][2],
		GLOBAL_AddrLocal[index][3],
		GLOBAL_AddrLocal[index][4],
		GLOBAL_AddrLocal[index][5]);
	return 0;
}

static int maclist_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file,maclist_proc_show,inode->i_private);
}

static ssize_t maclist_proc_write(struct file *file, const char *buffer, size_t len, loff_t *off)
{
	int user_len = 0;

	if (len > MAX_MACLIST_LENGTH)
	{
		user_len = MAX_MACLIST_LENGTH;
	}
	else
	{
		user_len = len;
	}
	if(copy_from_user(maclistbuffer, buffer, user_len)) //echo "s" > /proc/beaconmaclist
	{
		return -EFAULT;
	}
	return user_len;
}

static const struct file_operations maclist_proc_fops = {
	.owner = THIS_MODULE,
	.open = maclist_proc_open,
	.write = maclist_proc_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int wl_proc_init(void)
{
	if (procRegDir == NULL)
		//procRegDir = proc_mkdir(PROCREG_DIR, NULL);
		maclistbuffer = (char *)vmalloc(MAX_MACLIST_LENGTH);

	if(!maclistbuffer)
	{
		return -ENOMEM;
	}

	memset(maclistbuffer, 0, MAX_MACLIST_LENGTH);
	entry_wl_beacon_mac = proc_create("beaconmaclist", 0x0644, NULL, &maclist_proc_fops);
	if(entry_wl_beacon_mac)
	{
		mac_index = 0;
		mac_next = 0;
	}
	else
	{
		vfree(maclistbuffer);
    }

	return 0;
}

int wl_proc_exit(void)
{
	remove_proc_entry("beaconmaclist", entry_wl_beacon_mac);
	vfree(maclistbuffer);
	return 0;
}
#endif

