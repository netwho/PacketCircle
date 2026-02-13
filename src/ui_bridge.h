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

#ifndef UI_BRIDGE_H
#define UI_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations - avoid including headers that might have C++ issues */
typedef struct _capture_file capture_file;
typedef struct _analysis_result analysis_result_t;

/* C interface for UI functions */
void circle_vis_open_window(capture_file *cf);
void circle_vis_reload_data(void);
void circle_vis_update_analysis(analysis_result_t *result);
void circle_vis_close_window(void);

#ifdef __cplusplus
}
#endif

#endif /* UI_BRIDGE_H */
