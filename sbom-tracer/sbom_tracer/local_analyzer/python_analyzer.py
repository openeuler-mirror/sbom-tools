import os

from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.common_util import copy_definition_files
from sbom_tracer.util.const import PYTHON_DEFINITION_FILE_PATTERNS, DEFINITION_FILE_DIR_NAME
from sbom_tracer.util.log import logger


class PipAnalyzer(AnalyzerBase):
    def __init__(self):
        super(PipAnalyzer, self).__init__(r"^python((2|3)?|(2|3)+[\d.]+)$", r".*setup\.py.*", "")

    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        try:
            copy_definition_files(cwd, os.path.join(task_workspace, DEFINITION_FILE_DIR_NAME),
                                  PYTHON_DEFINITION_FILE_PATTERNS)
        except Exception as e:
            logger.warning("When handle [%s], an unknown exception occurs: %s", full_cmd, e, exc_info=True)
