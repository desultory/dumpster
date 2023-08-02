"""
Uses the netfilter module to parse logged packets,
acts on them.
"""

__version__ = '0.1.0'

import curses

from netfilter import NetfilterLogReader
from zen_custom import class_logger, add_thread, thread_wrapped


@add_thread('main', 'mainloop', 'Curses mainloop')
@class_logger
class CursesContainer:
    """
    Container for curses.
    Initializes curses similarly to curses.wrapper.
    The mainloop is controlled by the _stop_processing_main Event.
      This event is created by the add_thread decorator.
    """
    def __init__(self, title='CursesApp', *args, **kwargs):
        self.title = title
        self.mode = 'main'
        self.modes = {'m': self.mode}

    def run(self):
        """
        Initialize curses, the curses.wrapper doesn't seem to work well here
        """
        try:
            stdscr = curses.initscr()
            if curses.has_colors():
                self.init_colors()
            else:
                self.logger.warning('No color support.')

            stdscr.keypad(True)  # Enable keypad mode, for arrow keys
            curses.noecho()
            curses.cbreak()
            curses.curs_set(0)

            self.stdscr = stdscr
            self.logger.info('Curses initialized.')
            self.start_main_thread()
            self.threads['main'].join()
        except KeyboardInterrupt:
            self.logger.info("Detected KeyboardInterrupt, stopping main thread.")
            self.stop_main_thread()
        finally:
            self.clean_curses()

    def init_colors(self):
        """
        Initializes the colors for curses.
        """
        self.logger.info('Initializing colors')
        curses.start_color()
        curses.use_default_colors()
        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)  # offset by 1 to avoid 0

    def clean_curses(self):
        """
        Cleans the curses session
        """
        self.logger.info('Cleaning curses.')
        curses.echo()
        curses.nocbreak()
        curses.curs_set(1)
        curses.endwin()

    @thread_wrapped('main')
    def mainloop(self):
        """
        Main loop for the curses window.
        """
        self.stdscr.clear()
        self.draw_base_screen()

        if hasattr(self, f"mode_{self.mode}"):
            try:
                getattr(self, f"mode_{self.mode}")()
            except Exception as e:
                self.logger.exception(e)
        else:
            self.logger.error(f"Mode {self.mode} not found.")

        self.get_input()
        self.process_key()  # Always attempt to handle key processing

        self.stdscr.refresh()

    def mode_main(self):
        """
        Code for handling the main mode
        """
        pass

    def get_input(self):
        """
        Gets the input from the user.
        Saves it to self.key
        """
        self.stdscr.timeout(1000)
        try:
            self.key = self.stdscr.getkey()
        except curses.error:
            self.logger.log(5, "No key pressed before timeout.")
            self.key = None

    def process_key(self):
        """
        Process the key pressed.
        """
        self.stdscr.timeout(0)
        if self.key is None:
            self.logger.log(5, "No key pressed.")
            return

        if self.key.lower() == 'q':
            self.popup_window('Quit?', 'Are you sure you want to quit?', options=['y', 'n'])
            if self.key.lower() == 'y':
                self.stop_main_thread()

        if hasattr(self, f"process_key_{self.mode}"):
            try:
                if getattr(self, f"process_key_{self.mode}")():
                    return  # If the mode returns True, stop processing
            except Exception as e:
                self.logger.exception(e)

        if self.key.lower() in self.modes:
            mode = self.modes[self.key.lower()].replace(' ', '_')
            if not hasattr(self, f"mode_{mode}"):
                self.logger.error(f"Mode {mode} not found.")
            else:
                self.logger.info("Changing mode to %s" % mode)
                self.mode = mode
        else:
            self.logger.warning("Invalid key: %s" % self.key)

        self.key = None

    def draw_base_screen(self):
        """
        Draws the base screen.
        Makes a box around the screen.
        Inserts the title to the center of the top of the screen.
        """
        self.get_screen_size()
        self.stdscr.box()
        self.draw_title()
        self.draw_mode()

    def draw_mode(self):
        """
        Draws the current mode, starting on the second character of the top line, inside brackets.
        Lists possible modes at the bottom of the screen.
        """
        self.stdscr.addnstr(0, 1, '[%s]' % self.mode, self.cols - 2)

        offset = 1
        for key, mode in self.modes.items():
            if key == mode[0]:
                self.stdscr.addstr(self.rows - 1, offset, mode[0], curses.color_pair(21))
                offset += 1
                modestr = mode[1:] + ' '
                self.stdscr.addnstr(self.rows - 1, offset, modestr, self.cols - 2 - offset)
                offset += len(modestr)
            else:
                self.stdscr.addstr(self.rows - 1, offset, key + ':')
                offset += 2
                modestr = f' {mode} '
                self.stdscr.addnstr(self.rows - 1, offset, modestr, self.cols - 2 - offset)
                offset += len(modestr)

    def draw_title(self):
        """
        Draws the title, centered to the top of the screen.
        """
        self.stdscr.addnstr(0, self.cols // 2 - len(self.title) // 2, self.title, self.cols - 2)

    def get_screen_size(self):
        """ Get the screen size. """
        self.rows, self.cols = self.stdscr.getmaxyx()

    def popup_window(self, title='Popup', text='Text', options=None):
        """
        Creates a popup window.
        Waits for input and saves it to self.ket
        """
        popup_height = 5
        popup_width = max(len(title), len(text) + 2) + 2
        popup_x = self.cols // 2 - popup_width // 2
        popup_y = self.rows // 2 - popup_height // 2

        popup = self.stdscr.derwin(popup_height, popup_width, popup_y, popup_x)

        popup.clear()
        popup.box()
        popup.addnstr(0, popup_width // 2 - len(title) // 2, title, popup_width - 2)
        popup.addnstr(2, 2, text, popup_width - 2)

        if options == ['y', 'n']:
            # Draw a green 'y' and a red 'n' on the bottom line

            popup.addstr(popup_height - 1, popup_width // 2, 'y', curses.color_pair(3))
            popup.addstr(popup_height - 1, popup_width // 2 + 2, 'n', curses.color_pair(2))
        else:
            # Draw a centered prompt on the bottom line, containing the possible options
            prompt = '-'.join(options)
            prompt = f"[{prompt}]"
            popup.addnstr(popup_height - 1, popup_width // 2 - len(prompt) // 2, prompt, popup_width - 2)
        popup.refresh()
        self.popup = popup

        if options:
            while key := self.popup.getkey():
                if key.lower() in options:
                    self.key = key
                    break
                else:
                    self.logger.debug("Invalid option: %s" % key)
        else:
            self.get_input()


class Dumpster(CursesContainer):
    def __init__(self, *args, **kwargs):
        super().__init__(title='Dumpster', *args, **kwargs)

        self.log_items = []
        self.log_pos = 0
        self.log_offset = 0

        self.log_reader = NetfilterLogReader(logger=self.logger)
        self.log_reader.start_watch_thread()

        self.modes['l'] = 'log view'

    def stop_main_thread_actions(self):
        self.log_reader.stop_watch_thread()

    def process_log_queue(self):
        """
        Reads the items from the  log_reader.log_items queue and adds them to self.log_items
        """
        if not self.log_reader.log_items.empty():
            self.logger.debug("Processing log queue.")
            while not self.log_reader.log_items.empty():
                self.log_items.append(self.log_reader.log_items.get())
            self.logger.debug("Finished processing log queue.")
        self.logger.log(5, "Log queue empty.")

    def mode_log_view(self):
        """
        Displays the log items.
        """
        def display_log():
            """
            Displays the log items.
            """
            # Draws the arrow in the left margin
            self.stdscr.addstr(self.log_pos - self.log_offset + 1, 0, '⇰', curses.color_pair(6))
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

    def process_key_log_view(self):
        """
        Processes the key presses in log view mode.
        """
        if self.key == 'KEY_UP':
            self.log_pos = max(0, self.log_pos - 1)
            self.logger.info("Log pos has been decreased to %s" % self.log_pos)
            return True
        elif self.key == 'KEY_DOWN':
            self.log_pos = min(len(self.log_items) - 1 - self.rows, self.log_pos + 1)
            self.logger.info("Log position has been increased to %s" % self.log_pos)
            return True
        elif self.key == 'KEY_PPAGE':
            self.log_pos = max(0, self.log_pos - self.rows)
            self.logger.info("Log position has been decreased to %s" % self.log_pos)
            return True
        elif self.key == 'KEY_NPAGE':
            self.log_pos = min(len(self.log_items) - 1 - self.rows, self.log_pos + self.rows)
            self.logger.info("Log position has been increased to %s" % self.log_pos)
            return True




