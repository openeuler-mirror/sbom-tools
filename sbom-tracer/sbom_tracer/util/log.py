import logging
import os.path
import time


logger = logging.getLogger("sbom_tracer")
log_file = None


class Formatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return "%s,%03d %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S", self.converter(record.created)), record.msecs, time.strftime("%Z"))


def init_logger(logfile):
    global logger, log_file
    log_file = logfile
    logger.setLevel(logging.INFO)

    try:
        os.makedirs(os.path.dirname(log_file))
    except OSError:
        pass
    if os.path.isfile(logfile):
        os.unlink(logfile)

    handler = logging.FileHandler(logfile)
    log_format = "[%(asctime)s][%(levelname)s][%(name)s][P%(process)d][T%(thread)d]" \
                 "[%(filename)s:%(lineno)d][%(module)s:%(funcName)s][%(message)s]"
    handler.setFormatter(Formatter(log_format))
    logger.addHandler(handler)
