/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018 GlobalLogic. All rights reserved.
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

#ifndef __CONNMANCTL_TETHERING_H
#define __CONNMANCTL_TETHERING_H

#include <dbus/dbus.h>

#ifdef __cplusplus
extern "C" {
#endif

void __connmanctl_tethering_clients_list(DBusMessageIter *iter);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMANCTL_TETHERING_H */
