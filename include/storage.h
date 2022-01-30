/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __CONNMAN_STORAGE_H
#define __CONNMAN_STORAGE_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

int connman_storage_init(char *dir, char *vpn_dir);
void connman_storage_cleanup(void);
char *connman_storage_dir(void);
char *connman_storage_vpn_dir(void);

gchar **connman_storage_get_services();
GKeyFile *connman_storage_load_service(const char *service_id);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_STORAGE_H */
