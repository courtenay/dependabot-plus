#!/bin/bash
# Fake sudo — logs the attempt and exits with error.
# This sits ahead of real sudo in PATH so any sudo call from install
# scripts gets intercepted.
echo "SUDO_ATTEMPT: user=$(whoami) cmd=$*" >> /var/log/sudo.log
echo "sudo: permission denied" >&2
exit 1
