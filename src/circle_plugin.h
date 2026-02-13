/*
 * PacketCircle - Wireshark Network Communication Visualization Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 * https://github.com/netwho/PacketCircle
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CIRCLE_PLUGIN_H
#define CIRCLE_PLUGIN_H

#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/plugins.h>
#include <glib.h>

/* Plugin version */
#define PLUGIN_VERSION_MAJOR 0
#define PLUGIN_VERSION_MINOR 2
#define PLUGIN_VERSION_MICRO 2

/* Plugin registration */
void plugin_register(void);
void plugin_reg_handoff(void);

/* Protocol registration */
extern int proto_circle_vis;

/* Preferences */
extern gboolean circle_vis_enabled;
extern gboolean circle_vis_auto_open;

#endif /* CIRCLE_PLUGIN_H */
