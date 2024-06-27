import json
import os
import shutil
import subprocess
import tarfile
import time

from sbom_tracer.local_analyzer.analyzer_factory import AnalyzerFactory
from sbom_tracer.util import log
from sbom_tracer.util.common_util import run_daemon, get_command_config, infer_kernel_source_dir, copy_definition_files
from sbom_tracer.util.const import EXECSNOOP_PATH, H2SNIFF_PATH, SSLSNIFF_PATH, PROJECT_NAME, \
    DEFINITION_FILE_PATTERNS, TRACE_DATA_DIR_NAME, DEFINITION_FILE_DIR_NAME
from sbom_tracer.util.log import logger
from sbom_tracer.util.shell_util import execute, execute_recursive


class BccTracer(object):
    def __init__(self, shell, workspace, kernel_source, task_id, shell_path):
        self.shell = shell
        self.workspace = workspace
        self.kernel_source = kernel_source
        self.shell_path = shell_path
        self.task_id = task_id
        self.task_workspace = self._init_task_workspace()
        self.combine_shell = "{}_{}.sh".format(self.task_id, PROJECT_NAME)
        self.config = get_command_config()

        self.execsnoop_log = os.path.join(self.task_workspace, TRACE_DATA_DIR_NAME, "execsnoop.log")
        self.sslsniff_log = os.path.join(self.task_workspace, TRACE_DATA_DIR_NAME, "sslsniff.log")
        self.h2sniff_log = os.path.join(self.task_workspace, TRACE_DATA_DIR_NAME, "h2sniff.log")
        self.locally_collected_info_log = os.path.join(self.task_workspace, TRACE_DATA_DIR_NAME,
                                                       "locally_collected_info.log")
        self.tar_file = os.path.join(self.task_workspace, "{}_tracer_result.tar.gz".format(self.task_id))
        self.trace_data_tar_file = os.path.join(self.task_workspace, "{}.tar.gz".format(TRACE_DATA_DIR_NAME))
        self.def_file_tar_file = os.path.join(self.task_workspace, "{}.tar.gz".format(DEFINITION_FILE_DIR_NAME))

        self.shell_main_pid = None
        self.task_project_dir = None

    def _init_task_workspace(self):
        task_workspace = os.path.join(self.workspace, self.task_id)
        try:
            os.makedirs(task_workspace)
        except OSError:
            pass
        for dir_name in (TRACE_DATA_DIR_NAME, DEFINITION_FILE_DIR_NAME):
            if os.path.exists(os.path.join(task_workspace, dir_name)):
                shutil.rmtree(os.path.join(task_workspace, dir_name))
            os.mkdir(os.path.join(task_workspace, dir_name))
        return task_workspace

    def trace(self):
        logger.info("Start to trace")
        if not self.init_tracer():
            logger.error("Failed to init tracer")
            raise Exception("Failed to init tracer")
        shell_exit_status = self.execute_cmd()
        self.stop_trace()
        self.collect_info()
        copy_definition_files(self.task_project_dir, os.path.join(self.task_workspace, DEFINITION_FILE_DIR_NAME),
                              DEFINITION_FILE_PATTERNS)
        self.tar()
        logger.info("End to trace")
        return shell_exit_status

    def init_tracer(self):
        logger.info("Start to init tracer")
        try:
            self.run_tracer()
        except Exception as e:
            logger.error("Failed to init tracer: %s", e, exc_info=True)
            self.stop_trace()
            return False

        time.sleep(3)
        logger.info("End to init trace")
        return True

    def run_tracer(self):
        logger.info("Start to run tracer")
        bcc_python_version = self.infer_bcc_python_version()
        logger.info("The python version of BCC is [python%s]", bcc_python_version)
        for tool, trace_log in [(EXECSNOOP_PATH, self.execsnoop_log), (SSLSNIFF_PATH, self.sslsniff_log),
                                (H2SNIFF_PATH, self.h2sniff_log)]:
            cmd = "sudo python{} {} --task-id {}".format(bcc_python_version, tool, self.task_id)
            kernel_source = self.kernel_source if self.kernel_source else infer_kernel_source_dir()
            if kernel_source:
                cmd = "sudo BCC_KERNEL_SOURCE={} python{} {} --task-id {}".format(
                    kernel_source, bcc_python_version, tool, self.task_id)
            logger.info("BCC_KERNEL_SOURCE: [%s]", kernel_source)
            run_daemon(execute, (cmd,), dict(stdout=open(trace_log, "w"), stderr=subprocess.PIPE))
        logger.info("End to run tracer")

    @classmethod
    def infer_bcc_python_version(cls):
        if execute("python2 -c '''try:\n from bcc import BPF\nexcept ImportError:\n from bpfcc import BPF'''",
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)[0] == 0:
            return 2
        elif execute("python3 -c '''try:\n from bcc import BPF\nexcept ImportError:\n from bpfcc import BPF'''",
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)[0] == 0:
            return 3
        else:
            logger.error("Can't infer the python version of BCC")
            raise Exception("Can't infer the python version of BCC")

    def execute_cmd(self):
        logger.info("Start to execute shell command: [%s], working dir: [%s]", self.shell, self.shell_path)
        file_path = os.path.join(self.shell_path, self.combine_shell)
        with open(file_path, "w") as f:
            f.write(self.shell)
        shell_exit_status, _, _ = execute("bash {}".format(self.combine_shell), cwd=self.shell_path)
        shutil.move(file_path, os.path.join(self.task_workspace, TRACE_DATA_DIR_NAME, self.combine_shell))
        logger.info("End to execute shell command, exit code: [%s]", shell_exit_status)
        return shell_exit_status

    def stop_trace(self):
        logger.info("Start to stop tracer subprocesses")
        for i in range(1, 4):
            if execute_recursive("ps -ewwf | grep 'task-id {}' | grep -v \"grep\"".format(self.task_id))[0] != 0:
                logger.info("End to stop tracer subprocesses")
                return
            logger.info("Try to stop subprocesses with 'kill -2' for the [%s] time", i)
            execute_recursive("ps -ewwf | grep 'task-id {}' | grep -v \"grep\" | awk '{{print $2}}' | "
                              "xargs sudo kill -2".format(self.task_id))
            time.sleep(3)

        count = 1
        while True:
            if execute_recursive("ps -ewwf | grep 'task-id {}' | grep -v \"grep\"".format(self.task_id))[0] != 0:
                logger.info("End to stop tracer subprocesses")
                return
            logger.info("Try to stop subprocesses with 'kill -9' for the [%s] time", count)
            execute_recursive("ps -ewwf | grep 'task-id {}' | grep -v \"grep\" | awk '{{print $2}}' | "
                              "xargs sudo kill -9".format(self.task_id))
            time.sleep(3)
            count += 1

    def collect_info(self):
        logger.info("Start to collect local info")
        if not os.path.isfile(self.execsnoop_log):
            logger.info("End to collect local info because [%s] doesn't exist", self.execsnoop_log)
            return

        with open(self.execsnoop_log, "r") as f, open(self.locally_collected_info_log, "w") as fw:
            while True:
                line = f.readline().strip()
                if not line:
                    break

                try:
                    cmd_dict = json.loads(line)
                except ValueError:
                    logger.warning("Invalid record: [%s]", line)
                    continue

                if not self.is_valid_record(cmd_dict):
                    continue

                if self.combine_shell in cmd_dict["full_cmd"]:
                    self.shell_main_pid = cmd_dict["pid"]
                    self.task_project_dir = cmd_dict["cwd"]

                if self.combine_shell in cmd_dict["full_cmd"] or self.shell_main_pid in cmd_dict["ancestor_pids"]:
                    if cmd_dict["cmd"] in self.config:
                        self.analyze_executed_command(cmd_dict["cmd"], cmd_dict["full_cmd"], cmd_dict["cwd"], fw,
                                                      self.task_workspace)
        logger.info("End to collect local info")

    @classmethod
    def is_valid_record(cls, cmd_dict):
        return all(cmd_dict.get(k) for k in ("pid", "ppid", "cmd", "full_cmd", "ancestor_pids"))

    @classmethod
    def analyze_executed_command(cls, cmd, full_cmd, cwd, fd, task_workspace):
        for analyzer in AnalyzerFactory.get_all_analyzers():
            analyzer().analyze(cmd, full_cmd, cwd, fd, task_workspace)

    def tar(self):
        logger.info("Start to tar trace data")
        for tf in [self.def_file_tar_file, self.trace_data_tar_file, self.tar_file]:
            if os.path.exists(tf):
                os.unlink(tf)
            os.mknod(tf)

        with tarfile.open(self.trace_data_tar_file, "w:gz") as trace_data_tar_file:
            trace_data_tar_file.add(os.path.join(self.task_workspace, TRACE_DATA_DIR_NAME), arcname=TRACE_DATA_DIR_NAME)

        with tarfile.open(self.def_file_tar_file, "w:gz") as def_file_tar_file:
            def_file_tar_file.add(os.path.join(self.task_workspace, DEFINITION_FILE_DIR_NAME),
                                  arcname=DEFINITION_FILE_DIR_NAME)

        with tarfile.open(self.tar_file, "w:gz") as tar_file:
            tar_file.add(self.trace_data_tar_file, arcname=os.path.basename(self.trace_data_tar_file))
            tar_file.add(self.def_file_tar_file, arcname=os.path.basename(self.def_file_tar_file))
            tar_file.add(log.log_file, arcname=os.path.basename(log.log_file))
        logger.info("End to tar trace data")
