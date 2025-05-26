import logging
from rich.logging import RichHandler


def initialize_logger():

  handler = RichHandler(
    show_time=False,
  )
  handler.setFormatter(
    logging.Formatter(
      fmt='| %(message)s' # rich will add the loglevel by default
    )
  )
  logger = logging.getLogger()
  logger.addHandler(handler)


loglevel_map = {
  'debug': logging.DEBUG,
  'info':  logging.INFO,
  'error': logging.ERROR,
  'stfu':  logging.CRITICAL
}

def set_loglevel(user_loglevel_choice):

  logging.getLogger().setLevel(
    loglevel_map.get(user_loglevel_choice, logging.INFO)
  )

