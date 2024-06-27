import os

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_NAME = os.path.basename(PROJECT_DIR)
DEFAULT_COMMAND_CONFIG = os.path.join(PROJECT_DIR, "conf/default_command_config.yml")

SSLSNIFF_PATH = os.path.join(PROJECT_DIR, "bcc/sslsniff.py")
H2SNIFF_PATH = os.path.join(PROJECT_DIR, "bcc/h2sniff.py")
EXECSNOOP_PATH = os.path.join(PROJECT_DIR, "bcc/execsnoop.py")

PYTHON_DEFINITION_FILE_PATTERNS = [r"^.*requirements.*\.txt$", r"^setup\.py$"]
MAVEN_DEFINITION_FILE_PATTERNS = [r"^pom\.xml$"]
GRADLE_DEFINITION_FILE_PATTERNS = [r"^build\.gradle$", r"^build\.gradle\.kts$",
                                   r"^settings\.gradle$", r"^settings\.gradle\.kts$",
                                   r"^gradle\.properties$", r"^libs\.versions\.toml$"]
DEFINITION_FILE_PATTERNS = PYTHON_DEFINITION_FILE_PATTERNS + MAVEN_DEFINITION_FILE_PATTERNS + \
                           GRADLE_DEFINITION_FILE_PATTERNS
DEFINITION_FILE_SUBSTR_BLACK_LIST = ["test", "example", "sample", "dev"]

TRACE_DATA_DIR_NAME = "trace_data"
DEFINITION_FILE_DIR_NAME = "definition_file"
