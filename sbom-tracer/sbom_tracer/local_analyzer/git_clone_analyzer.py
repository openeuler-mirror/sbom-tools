import json
import os
import re
import subprocess
from argparse import ArgumentParser

from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.log import logger
from sbom_tracer.util.shell_util import execute

# A 'git clone' command parser
# https://git-scm.com/docs/git-clone
parser = ArgumentParser()
parser.add_argument("-l", "--local", action="store_true")
parser.add_argument("--no-hardlinks", action="store_true")
parser.add_argument("-s", "--shared", action="store_true")
parser.add_argument("--reference")
parser.add_argument("--reference-if-able")
parser.add_argument("--dissociate", action="store_true")
parser.add_argument("-q", "--quiet", action="store_true")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("--progress", action="store_true")
parser.add_argument("--server-option")
parser.add_argument("-n", "--no-checkout", action="store_true")
parser.add_argument("--reject-shallow", action="store_true")
parser.add_argument("--no-reject-shallow", action="store_true")
parser.add_argument("--bare", action="store_true")
parser.add_argument("--sparse", action="store_true")
parser.add_argument("--filter")
parser.add_argument("--also-filter-submodules", action="store_true")
parser.add_argument("--mirror", action="store_true")
parser.add_argument("-o", "--origin")
parser.add_argument("-b", "--branch")
parser.add_argument("-u", "--upload-pack")
parser.add_argument("--template")
parser.add_argument("-c", "--config")
parser.add_argument("--depth")
parser.add_argument("--shallow-since")
parser.add_argument("--shallow-exclude")
parser.add_argument("--single-branch", action="store_true")
parser.add_argument("--no-single-branch", action="store_true")
parser.add_argument("--no-tags", action="store_true")
parser.add_argument("--recurse-submodules", action="store_true")
parser.add_argument("--recursive", action="store_true")
parser.add_argument("--shallow-submodules", action="store_true")
parser.add_argument("--no-shallow-submodules", action="store_true")
parser.add_argument("--remote-submodules", action="store_true")
parser.add_argument("--no-remote-submodules", action="store_true")
parser.add_argument("--separate-git-dir")
parser.add_argument("-j", "--jobs")
parser.add_argument("repository")
parser.add_argument("directory", nargs="?")


class GitCloneAnalyzer(AnalyzerBase):
    def __init__(self):
        super(GitCloneAnalyzer, self).__init__(r"^git$", r"git\s*clone.*", "git_clone")

    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        try:
            git_clone_dir = self._infer_git_clone_dir(full_cmd)
            os.chdir(os.path.join(cwd, git_clone_dir))
            version_string = execute("%s describe --tags --always" % full_cmd.strip().split()[0],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)[1].strip()
            commit_id = execute("%s rev-parse --short HEAD" % full_cmd.strip().split()[0],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)[1].strip()
            url = execute("%s config --get remote.origin.url" % full_cmd.strip().split()[0],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)[1].strip()
            fd.write(json.dumps(dict(commit_id=commit_id, version_string=version_string, url=url, tag=self.tag)) + "\n")
        except Exception as e:
            logger.warning("When handle [%s], an unknown exception occurs: %s", full_cmd, e, exc_info=True)

    @classmethod
    def _infer_git_clone_dir(cls, full_cmd):
        result, unknown = parser.parse_known_args(re.search(r"git\s*clone(.*)", full_cmd).group(1).split())
        if result.directory:
            return result.directory
        if unknown:
            # intermixed command, e.g., git clone https://github.com/iovisor/bcc.git -b master bcc
            return unknown[0]
        return result.repository.split("/")[-1].replace(".git", "")
