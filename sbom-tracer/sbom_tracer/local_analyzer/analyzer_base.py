import re
from abc import ABCMeta, abstractmethod

import six


@six.add_metaclass(ABCMeta)
class AnalyzerBase(object):
    def __init__(self, cmd_regex, full_cmd_regex, tag):
        self.cmd_regex = cmd_regex
        self.full_cmd_regex = full_cmd_regex
        self.tag = tag

    def match(self, cmd, full_cmd):
        return re.match(self.cmd_regex, cmd) and re.search(self.full_cmd_regex, full_cmd)

    def analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        if not self.match(cmd, full_cmd):
            return
        self._analyze(cmd, full_cmd, cwd, fd, task_workspace)

    @abstractmethod
    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        pass
