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
            if curses.has_colors:
                curses.start_color()

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
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)

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
                getattr(self, f"process_key_{self.mode}")()
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
                self.stdscr.addstr(self.rows - 1, offset, mode[0], curses.color_pair(3))
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

        # Draw a centered prompt on the bottom line, containing the possible options
        if options:
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
        max_log_items = self.rows - 2

        self.process_log_queue()
        if not self.log_items:
            self.logger.info("No log items.")
            self.stdscr.addnstr(1, 1, 'No log items.', self.cols - 2)
            return

        offset = max(0, min(self.log_offset, len(self.log_items) - max_log_items))

        for i, log_item in enumerate(self.log_items[offset:min(len(self.log_items), max_log_items) + offset]):
            self.stdscr.addnstr(i + 1, 1, str(log_item), self.cols - 2)

    def process_key_log_view(self):
        """
        Processes the key presses in log view mode.
        """
        if self.key == 'KEY_UP':
            self.log_offset = max(0, self.log_offset - 1)
            self.logger.info("Log offset has been decreased to %s" % self.log_offset)
        elif self.key == 'KEY_DOWN':
            self.log_offset = min(len(self.log_items) - 1 - self.rows, self.log_offset + 1)
            self.logger.info("Log offset has been increased to %s" % self.log_offset)

