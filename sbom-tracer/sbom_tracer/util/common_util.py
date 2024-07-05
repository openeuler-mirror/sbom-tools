import os
import re
import shutil
import time
from threading import Thread

import yaml

from sbom_tracer.util.const import DEFAULT_COMMAND_CONFIG, DEFINITION_FILE_SUBSTR_BLACK_LIST
from sbom_tracer.util.log import logger


class ThreadWithResult(Thread):
    def __init__(self, target, args, kwargs):
        super(ThreadWithResult, self).__init__()
        self._target = target
        self._args = args
        self._kwargs = kwargs
        self._result = None

    def run(self):
        try:
            self._result = self._target(*self._args, **self._kwargs)
        except Exception as e:
            logger.error(e, exc_info=True)
        finally:
            del self._target, self._args, self._kwargs

    def get_result(self):
        return self._result


def run_daemon(target, args, kwargs):
    thread = ThreadWithResult(target=target, args=args, kwargs=kwargs)
    thread.daemon = True
    thread.start()

    time.sleep(3)
    if not thread.is_alive():
        logger.error("Failed to run command as daemon: %s", thread.get_result())
        raise Exception("Failed to run command as daemon")


def get_command_config():
    with open(DEFAULT_COMMAND_CONFIG, "r") as f:
        return yaml.safe_load(f)


def infer_kernel_source_dir():
    link_path = "/lib/modules/{}/build".format(os.uname()[2])
    if os.path.isdir(link_path):
        return link_path
    kernel_home = "/usr/src/kernels"
    if not os.path.isdir(kernel_home):
        return None
    if not os.listdir(kernel_home):
        return None
    return os.path.join(kernel_home, sorted(os.listdir(kernel_home), reverse=True)[0])


def copy_definition_files(src_dir, dst_dir, definition_file_patterns):
    for f in os.listdir(src_dir):
        _copy_definition_file(f, src_dir, dst_dir, definition_file_patterns)


def copy_definition_files_recursively(src_dir, dst_dir, definition_file_patterns):
    for root, _, files in os.walk(src_dir):
        if any(sub_str in root.lower() for sub_str in DEFINITION_FILE_SUBSTR_BLACK_LIST):
            continue
        for f in files:
            _copy_definition_file(f, root, dst_dir, definition_file_patterns)


def _copy_definition_file(f, src_dir, dst_dir, definition_file_patterns):
    if any(sub_str in f.lower() for sub_str in DEFINITION_FILE_SUBSTR_BLACK_LIST):
        return
    if re.match("|".join(definition_file_patterns), f):
        target_dir = os.path.join(dst_dir, src_dir.lstrip("/"))
        if not os.path.exists(target_dir):
            try:
                os.makedirs(target_dir)
            except OSError:
                pass
        logger.info("Copy [%s] from [%s] to [%s]", f, src_dir, target_dir)
        shutil.copy(os.path.join(src_dir, f), target_dir)
