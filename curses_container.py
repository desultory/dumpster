"""
Async container for curses.
"""

__version__ = '0.1.0'

import curses
from asyncio import Event, sleep

from zenlib.logging import loggify


@loggify
class CursesContainer:
    """
    Container for curses.
    Initializes curses similarly to curses.wrapper.
    Runs the main loop.
    """
    def __init__(self, title='CursesApp', *args, **kwargs):
        self.title = title
        self.mode = 'main'
        self.modes = {'m': self.mode}
        self.stop = Event()

    async def run(self):
        """ Initialize curses, run the mainloop forever. """
        self.init_curses()
        self.additional_run()
        while not self.stop.is_set():
            await self.mainloop()
        self.clean_curses()

    def additional_run(self):
        """ override this method to add additional functionality to the run method. """
        pass

    def init_curses(self):
        """ Initialize curses. """
        try:
            stdscr = curses.initscr()
            if curses.has_colors():
                self._init_colors()
            else:
                self.logger.warning('No color support.')

            stdscr.keypad(True)  # Enable keypad mode, for arrow keys
            stdscr.nodelay(True)  # Non-blocking input
            curses.noecho()
            curses.cbreak()
            curses.curs_set(0)

            self.stdscr = stdscr
            self.logger.info('Curses initialized.')
        except KeyboardInterrupt:
            self.logger.info("Detected KeyboardInterrupt, stopping main thread.")
            self.stop.set()

    def _init_colors(self):
        """ Initializes the colors for curses. """
        self.logger.info('Initializing colors')
        curses.start_color()
        curses.use_default_colors()
        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)  # offset by 1 to avoid 0

    def clean_curses(self):
        """ Cleans the curses session. """
        self.logger.info('Cleaning curses.')
        curses.echo()
        curses.nocbreak()
        curses.curs_set(1)
        curses.endwin()

    async def mainloop(self):
        """ Main loop for the curses window. """
        self.draw_base_screen()  # Draw the base screen

        if hasattr(self, f"mode_{self.mode}"):  # Process the current mode
            try:
                getattr(self, f"mode_{self.mode}")()
            except Exception as e:
                self.logger.exception(e)
        else:
            self.logger.error(f"Mode {self.mode} not found.")

        await self.handle_input()
        self.stdscr.refresh()

    def mode_main(self):
        """ Code for handling the main mode. """
        pass

    async def get_input(self):
        """ Gets a character from the user. """
        while not self.stop.is_set():
            try:
                char = self.stdscr.getkey()
            except curses.error:
                self.logger.log(5, "No key pressed before timeout.")
                await sleep(0.05)
            else:
                break
        self.logger.debug("Key pressed: %s" % char)
        return char

    async def handle_input(self):
        """ Gets the input from the user. """
        await self.process_key(await self.get_input())

    async def process_key(self, key):
        """  Process the pressed key. """
        if key.lower() == 'q':
            if await self.popup_window('Quit?', 'Are you sure you want to quit?', options=['y', 'n']) == 'y':
                self.stop.set()
                self.logger.warning("Got stop signal.")
                return

        if hasattr(self, f"process_key_{self.mode}"):
            try:
                if getattr(self, f"process_key_{self.mode}")(key):
                    return  # If the mode returns True, stop processing
            except Exception as e:
                self.logger.exception(e)

        if key.lower() in self.modes:
            mode = self.modes[key.lower()].replace(' ', '_')
            if not hasattr(self, f"mode_{mode}"):
                self.logger.error(f"Mode {mode} not found.")
            else:
                self.logger.info("Changing mode to %s" % mode)
                self.mode = mode
        else:
            self.logger.warning("Invalid key: %s" % key)

    def draw_base_screen(self):
        self.get_screen_size()  # Get the screen size
        self.stdscr.clear()    # Clear the screen
        self.stdscr.box()    # Draw a box around the screen
        self.draw_title()   # Draw the title
        self.draw_mode()    # Draw the mode

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
        """ Draws the title, centered to the top of the screen. """
        self.stdscr.addnstr(0, self.cols // 2 - len(self.title) // 2, self.title, self.cols - 2)

    def get_screen_size(self):
        """ Get the screen size. """
        self.rows, self.cols = self.stdscr.getmaxyx()

    async def popup_window(self, title='Popup', text='Text', options=None):
        """
        Creates a popup window.
        Waits for input and returns it.
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
            key = await self.get_input()
            if key.lower() in options:
                return key
            else:
                self.logger.debug("Invalid option: %s" % key)
        else:
            return await self.get_input()

