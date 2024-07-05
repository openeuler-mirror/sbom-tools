#!/usr/bin/env bash

init() {
  if [[ "$(expr substr "$(uname -s)" 1 5)" == "MINGW" ]]; then
    echo "sbom_tracer does not support windows now"
    exit 1
  fi

  if [ -f /etc/redhat-release ]; then
    DISTRO="RedHat"
    PACKAGE_MANAGER_APP="yum"
  elif [ -f /etc/openEuler-release ]; then
    DISTRO="openEuler"
    PACKAGE_MANAGER_APP="yum"
  elif [ -f /etc/euleros-release ]; then
    DISTRO="euleros"
    PACKAGE_MANAGER_APP="yum"
  elif [ -f /etc/debian_version ]; then
    DISTRO="Debian"
    PACKAGE_MANAGER_APP="apt-get"
  else
    echo "unsupported linux version"
    exit 1
  fi
}

install_bcc() {
  echo "======install bcc begin======"
  if [ "${DISTRO}" == "RedHat" ] || [ "${DISTRO}" == "openEuler" ] || [ "${DISTRO}" == "euleros" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install gnutls
    sudo ${PACKAGE_MANAGER_APP} -y install bcc
    sudo ${PACKAGE_MANAGER_APP} -y install kernel-devel
    sudo ${PACKAGE_MANAGER_APP} -y install kernel-devel-$(uname -r)
    sudo ${PACKAGE_MANAGER_APP} -y install kernel-headers
    sudo ${PACKAGE_MANAGER_APP} -y install kernel-headers-$(uname -r)
  elif [ "${DISTRO}" == "Debian" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install gnutls-bin
    sudo ${PACKAGE_MANAGER_APP} -y install bpfcc-tools
    sudo ${PACKAGE_MANAGER_APP} -y install linux-headers
    sudo ${PACKAGE_MANAGER_APP} -y install linux-headers-$(uname -r)
  fi

  if [ "${DISTRO}" == "RedHat" ] || [ "${DISTRO}" == "openEuler" ] || [ "${DISTRO}" == "euleros" ]; then
    if [ ! -d /usr/share/bcc ]; then
      echo "install bcc error"
      exit 1
    fi
  fi

  if [ "${DISTRO}" == "Debian" ]; then
      if [ ! -f /usr/sbin/execsnoop-bpfcc ] && [ ! -f /sbin/execsnoop-bpfcc ]; then
        echo "install bcc error"
        exit 1
      fi
  fi

  infer_bcc_python_version

  echo "======install bcc success======"
}

infer_bcc_python_version() {
  python2 -c '''
try:
   from bcc import BPF
except ImportError:
   from bpfcc import BPF
  ''' > /dev/null 2>&1

  if [ $? -eq 0 ]; then
    PYTHON_MAJOR_VERSION="2"
  fi

  python3 -c '''
try:
   from bcc import BPF
except ImportError:
   from bpfcc import BPF
  ''' > /dev/null 2>&1

  if [ $? -eq 0 ]; then
    PYTHON_MAJOR_VERSION="3"
  fi

  if [ "${PYTHON_MAJOR_VERSION}"x == x ]; then
    echo "install python bcc error"
    exit 1
  fi
}

install_pip() {
  echo "======install pip begin======"
  if [ "${DISTRO}" == "RedHat" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install epel-release
  fi

  if [ "${PYTHON_MAJOR_VERSION}" == "3" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install python3-pip
    sudo python3 -m pip install --upgrade pip
  else
    if [ "${DISTRO}" == "Debian" ]; then
      sudo ${PACKAGE_MANAGER_APP} -y install python-pip
    else
      sudo ${PACKAGE_MANAGER_APP} -y install python2-pip
    fi
    sudo python2 -m pip install --upgrade "pip<21.0"
  fi
  echo "======install pip success======"
}

install_sbom_tracer() {
  echo "======install sbom_tracer begin======"
  sudo python${PYTHON_MAJOR_VERSION} -m pip install wheel
  sudo python${PYTHON_MAJOR_VERSION} setup.py bdist_wheel
  sudo python${PYTHON_MAJOR_VERSION} -m pip uninstall -y sbom_tracer
  sudo python${PYTHON_MAJOR_VERSION} -m pip install dist/sbom_tracer-*-py*-none-any.whl

  if ! sudo sbom_tracer --help; then
    if ! sbom_tracer --help; then
      echo "install sbom_tracer error"
      exit 1
    fi
  fi
  echo "======install sbom_tracer success======"
}

DISTRO=""
PACKAGE_MANAGER_APP=""
PYTHON_MAJOR_VERSION=""
init
install_bcc
install_pip
install_sbom_tracer
