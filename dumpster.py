"""
Uses the netfilter module to parse logged packets,
acts on them.
"""

__version__ = '0.1.0'

import curses

from netfilter import NetfilterLogReader
from curses_container import CursesContainer


class Dumpster(CursesContainer):
    def __init__(self, *args, **kwargs):
        super().__init__(title='Dumpster', *args, **kwargs)

        self.log_items = []
        self.log_pos = 0
        self.log_offset = 0

        self.log_reader = NetfilterLogReader(logger=self.logger)
        self.modes['l'] = 'log view'

    def additional_run(self):
        self.log_reader.watch_logs()

    def process_log_queue(self):
        """ Reads the items from the  log_reader.log_items queue and adds them to self.log_items. """
        if not self.log_reader.log_items.empty():
            self.logger.debug("Processing log queue.")
            while not self.log_reader.log_items.empty():
                self.log_items.append(self.log_reader.log_items.get())
            self.logger.debug("Finished processing log queue.")
        self.logger.log(5, "Log queue empty.")

    def mode_log_view(self):
        """  Displays the log items. """
        def display_log():
            """  Displays the log items.  """
            # Draws the arrow in the left margin
            self.stdscr.addstr(self.log_pos - self.log_offset + 1, 0, '➤', curses.color_pair(6))
            self.logger.log(5, "Drawing log items from %s to %s" % (self.log_offset, min(len(self.log_items), self.rows - 2) + self.log_offset))

            log_items = self.log_items[self.log_offset:min(len(self.log_items), self.rows - 2) + self.log_offset]
            host_width = max([len(log_item.hostname) for log_item in log_items])
            base_offset = 20 + host_width  # 19 comes from the timestamp width

            color_set_red = (197, 125, 161)
            color_set_green = (46, 27, 34)
            color_set_f_src = (203, 71, 83)
            color_set_f_dst = (23, 209, 221)

            for i, log_item in enumerate(log_items):
                self.logger.log(5, "[%s] Displaying log item: %s" % (i, log_item))

                # Draw the timestamp
                self.stdscr.addstr(i + 1, 1, log_item.timestamp, curses.color_pair(12))

                # Draw the hostname
                self.stdscr.addstr(i + 1, 20, log_item.hostname, curses.color_pair(59))

                # Get some information about the log item
                src_mac = log_item.display_src_mac()
                src_ip = log_item.display_src_ip()

                dst_mac = log_item.display_dst_mac()
                dst_ip = log_item.display_dst_ip()

                # Set the source color based on the direction/type
                direction = log_item.log_type
                if direction == 'inbound':
                    color_set = color_set_red
                elif direction == 'outbound':
                    color_set = color_set_green
                else:
                    color_set = color_set_f_src

                # Draw the source information
                self.stdscr.addstr(i + 1, base_offset + 1, direction, curses.color_pair(color_set[0]))
                self.stdscr.addstr(i + 1, base_offset + 10, src_mac, curses.color_pair(color_set[1]))
                self.stdscr.addstr(i + 1, base_offset + 28, src_ip, curses.color_pair(color_set[2]))
                self.stdscr.addstr(i + 1, base_offset + 28 + len(src_ip), f":{log_item.display_src_port()}", curses.color_pair(color_set[0]))

                # Draw the destination information
                if direction == 'inbound':
                    color_set = color_set_green
                elif direction == 'outbound':
                    color_set = color_set_red
                else:
                    color_set = color_set_f_dst

                self.stdscr.addstr(i + 1, base_offset + 50, dst_mac, curses.color_pair(color_set[1]))
                self.stdscr.addstr(i + 1, base_offset + 68, dst_ip, curses.color_pair(color_set[2]))
                self.stdscr.addstr(i + 1, base_offset + 68 + len(dst_ip), f":{log_item.display_dst_port()}", curses.color_pair(color_set[0]))

        self.process_log_queue()
        if not self.log_items:
            self.logger.info("No log items.")
            self.stdscr.addnstr(1, 1, 'No log items.', self.cols - 2)
            return

        # if the log position is greater than the current offset + the screen size, increase the offset
        # If the log position is less than the current offset, decrease the offset
        if self.log_pos >= self.log_offset + self.rows - 2:
            self.log_offset = self.log_pos - self.rows + 3
            self.logger.debug("Log offset has been increased to %s" % self.log_offset)
        elif self.log_pos < self.log_offset:
            self.log_offset = self.log_pos
            self.logger.debug("Log offset has been decreased to %s" % self.log_offset)

        display_log()

    def process_key_log_view(self, key):
        """  Processes the key presses in log view mode. """
        self.logger.error(key)
        if key == 'KEY_UP':
            self.log_pos = max(0, self.log_pos - 1)
            self.logger.info("Log pos has been decreased to %s" % self.log_pos)
            return True
        elif key == 'KEY_DOWN':
            self.log_pos = min(len(self.log_items) - 1 - self.rows, self.log_pos + 1)
            self.logger.info("Log position has been increased to %s" % self.log_pos)
            return True
        elif key == 'KEY_PPAGE':
            self.log_pos = max(0, self.log_pos - self.rows)
            self.logger.info("Log position has been decreased to %s" % self.log_pos)
            return True
        elif key == 'KEY_NPAGE':
            self.log_pos = min(len(self.log_items) - 1 - self.rows, self.log_pos + self.rows)
            self.logger.info("Log position has been increased to %s" % self.log_pos)
            return True




