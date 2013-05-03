/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifndef __CONNMANCTL_DBUS_HELPERS_H
#define __CONNMANCTL_DBUS_HELPERS_H

#include <dbus/dbus.h>

#ifdef __cplusplus
extern "C" {
#endif

void __connmanctl_dbus_print(DBusMessageIter *iter, const char *pre,
		const char *dict, const char *sep);

typedef void (*connmanctl_dbus_method_return_func_t)(DBusMessageIter *iter,
		const char *error, void *user_data);
int __connmanctl_dbus_method_call(DBusConnection *connection, const char *path,
		const char *interface, const char *method,
		connmanctl_dbus_method_return_func_t cb, void * user_data,
		int arg1, ...);

int __connmanctl_dbus_set_property(DBusConnection *connection,
		const char *path, const char *interface,
		connmanctl_dbus_method_return_func_t cb, void * user_data,
		const char *property, int type, void *value);

typedef void (*connmanctl_dbus_append_func_t)(DBusMessageIter *iter,
		void *user_data);

void __connmanctl_dbus_append_dict_entry(DBusMessageIter *iter,
		const char *property, int type, void *value);
int __connmanctl_dbus_set_property_dict(DBusConnection *connection,
		const char *path, const char *interface,
		connmanctl_dbus_method_return_func_t cb, void * user_data,
		const char *property, int type,
		connmanctl_dbus_append_func_t append_fn,
		void *append_user_data);

void __connmanctl_dbus_append_dict_string_array(DBusMessageIter *iter,
		const char *property, connmanctl_dbus_append_func_t append_fn,
		void *append_user_data);
int __connmanctl_dbus_set_property_array(DBusConnection *connection,
		const char *path, const char *interface,
		connmanctl_dbus_method_return_func_t cb, void *user_data,
		const char *property, int type,
		connmanctl_dbus_append_func_t append_fn,
		void *append_user_data);

#ifdef __cplusplus
}
#endif

#endif
