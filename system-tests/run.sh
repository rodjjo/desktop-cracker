#!/bin/bash
# system-tests/run.sh — the one-pass system test (`AGENTS.md`, "System testing").
#
# There is **one** test file, `system-tests/system-tests.py`, and one boot in it: a microVM takes
# half a minute to reach its desktop, so a design that boots it once per feature makes the suite
# slow and the project unmaintainable.  The steps are named, they run in order in the single pass,
# and any of them may be skipped or run alone.
#
#   make system-tests                          every step
#   make system-tests SYSTEM_TEST_ARGS=--list  the step names
#   make system-tests SYSTEM_TEST_ARGS="--only boot-and-wrong-password"
#   make system-tests SYSTEM_TEST_ARGS="--skip window-actions"
#
# What it needs: `/dev/kvm`, the application and the plugin built (`make build`), and the guest's
# media (`make download`, which `make system-tests` depends on).  It asks the **person** for the
# root disk's passphrase, which is the only place that secret exists: it is typed here, handed to
# the application as the answer to its own question over the plugin, and never written to a file,
# an environment variable or a command line (`AGENTS.md`, "Environment variables").
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
test_py="$root/system-tests/system-tests.py"

if [ ! -r /dev/kvm ]; then
    echo "system-tests: /dev/kvm is not readable — the microVM tests cannot run here"
    echo "system-tests: add yourself to the 'kvm' group (sudo usermod -aG kvm $(id -un)) and log in again"
    exit 2
fi

if [ ! -f "$test_py" ]; then
    echo "system-tests: $test_py is missing" >&2
    exit 2
fi

# The run's own directory: the project's `temp/`, never the system's `/tmp` (`AGENTS.md`: a
# test's scratch belongs beside the project).
run_dir=${SYSTEM_TEST_RUN_DIR:-$root/temp/system-test}
exec python3 "$test_py" --run-dir "$run_dir" ${SYSTEM_TEST_ARGS:-}
