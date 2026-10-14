# Project rules

These are rules for the whole tree, tests included. They are not style preferences: a change that
bends one of them is a change that should be refused, and if a rule really has to change, the
design changes with it.

Why does this project exist, why we use microvm instead of standard vms ?
Standard VMs take longer to boot, microvm boots faster. 
if our microvm is taking longer to boot, we need to investigate, we neet to make sure it boots with very few seconds, thats the reason why we are using microvms. 
We need to make sure our CPUs do not stuck while runnign the VM, if our VM is more than 10 seconds to boot, there is something wrong that needs to be investigated and justified. We need to check softlocks making the CPUs to stuck and also investigate any other causes.

What are the main components of this project ?

1) firecracker - Runs our microvm (a released binary; every guest device is a channel this
   process serves over vsock).
2) desktop-cracker - starts firecracker and controls our microvm that runs on it.

What happens if we kill the process of desktop-cracker ?
the firecracker instance dies together: a firecracker instance desktop-cracker started is never an orphan, the child processes are tied to the parent execution (`PR_SET_PDEATHSIG`).

What happens if desktop-cracker crashes and the process ends ?
the child processes are tied to the parent execution, so the child firecracker instance also dies.

## Environment variables

Do not save any password/credential at environment variables, do not save them at disk (even in regions that are memory RAM, ramfs).
We only pass credentials in qmp to mount the root disk using "qmp object-add secret", that's the only place we use the credentials the user typed.

Read on:

* **Nothing the application reads, writes or passes on may hold a credential**: not the settings
  file, not a log, not a command line argument, not a file in `temp/`, not a test fixture in
  `test-data/`.
* A credential lives in memory, for as long as it is needed, and is zeroized when it is dropped.
  It goes to the guest through the control share (which the guest removes) or through
  `qmp object-add secret` — those are the only two ways out of the process.
* `DESK_PLUGIN_PORT` is the one environment variable this project has, it belongs to the
  plugin, and it carries a port, never a credential. Do not add
  others, and do not add any for the application.
* This binds the tests too: a system test must never write a passphrase to a file or pass it in an
  environment variable. The passphrase is typed to the test by the person running it, and the test
  hands it to the application as an answer to the application's own dialog, over the plugin.

## Debugging

Do not add logs nor debugging code in our project directly, do not ship code that save files or save logs in our application code.
This application is not suppose to flood the disk with logs or flood the stdout with debugging information. desk-disk can have log in stdout as well, it is a tool not the main application.
We are not suppose to add modes or parameters to our application for debugging purposes, the application should have no other operation modes than the designed
mode:
    It always opens a graphical environment with a display.
    It always uses encrypted disks.
    It have no timeouts to run nor sleep nor anything that controls it for tests purpose.

The parameters that the application has are used for its normal use (like --plugin-path, --run-seconds) and so on, those use are not for debugging purpose so ok. There is **one run mode**; the `--admin` and `--no-network` switches of the read-only era were removed on 2026-10-08 (the guest filesystem is always read-write and the network is always attached), so a switch that selects between modes no longer exists to be added.

We need to avoid our application being flooded with testing code, debugging code that are making the code complex and complex over the time.
The application does not create any file on disk, it only create filesockets and only the needed ones.
folders created to be used in volumes are ok, they are not for test purposes.

Read on:

* **The application's switches are a closed list.** The `dc-cli` crate holds them,
  holds them, and the switches that exist for driving a run
  from a script (`--display`, `--numlock-held`, `--window-command`, `--run-seconds`,
  `--ready-file`, …) are ordinary run knobs, documented in `dc-cli` and reachable by a user.
  Adding a switch for a test's convenience — or an environment variable, or a hidden file, or a
  "debug" build — is forbidden: it needs a change to the project's rules first, and it has to be something
  a normal user would want.
* **What the application prints is what a person needs** (milestones and errors) — never a
  per-frame, per-packet or per-call trail. If a question needs more than that to answer, the
  answer is `--plugin-path`, an external tool, or the VMM's own tracing, not a print in the
  application.
* **Nothing is written to disk by the application**: no log file, no dump, no screenshot, no
  serial log, no scratch directory inside a run. The only files are the sockets it needs, the
  volumes/folders the user asked for, and the settings file.
* **The software-only rules are not negotiable, not even in a test**: the run always opens a
  display path and always uses encrypted disks. There is no "faster test mode" that skips a disk,
  and there is no mode that runs without the graphical environment.
* A **postmortem or investigation** does not leave instrumentation behind. Diagnostics used to
  settle a bug (`DESK_FRAME_PROBE`, `DESK_SCANOUT_LOG`, the frame probe's PNG, a serial
  log) are removed with the bug, and what was learned goes into the postmortem and into
  the plugin's hooks — which is where the next investigation should start.

## Unit testing

Unit tests tests feature isolated in a fast way, unit tests does not use sleep or wait for something, it just tests static code without coupling the tests.
If unittests needs files, we store them at the root of the project in a folder called "test-data/".
Unit tests should mock the system, unit tests are suppose to test the code not the system. Unit tests are meant to be fast, not relying on sleep.
Use stable and well know libraries to write tests, google mock, pytests and so on depeding on the language of the code being tested.

Read on:

* **No KVM, no hypervisor, no guest, no network, no display server** in a unit test; those belong to the
  system test. What talks to the outside world (the API, the disk, the X server, the driver, the
  clock) sits behind a small trait or a function pointer so the test supplies a stub.
* **A unit test never reads or writes the user's settings** (`~/.desktop-cracker/`), `/tmp`,
  `/dev/kvm`, the display socket or the host's disks. Files it needs come from `test-data/`,
  read-only, and anything it must write goes to the test's own `tempfile` directory.
* **Only positive expectations.** No thread/task is started in a unit test that has to be joined,
  waited on or killed; no test spawns a process it must then sleep for. If a test needs a clock, a
  timeout or an ordering, the timing belongs to a parameter the test controls.
* Test names say what is asserted ("the plugin is looked for beside the binary"), so a failure
  reads as a sentence about the code.

## System testing

Never use the system temp directory for testing purposes we have "temp/" folder on this repository for that purpose.

We meed to avoid using sleep, and instead of using a long sleep we try to use retries with small sleeps of 200ms to check, so we never wait more than needed for something.

Desktop-cracker accepts an optional parameter called "--plugin-path".
The plugin is designed to help our agent to system test the application without flooding the application with debug code nor printing logs nor saving files.
How the plugin works: the crate is `desktop-cracker/plugin/`, and the application
reaches it through `--plugin-path`.

TOOLS STILL CAN HAVE LOGS to stdout/stderr, we just do not want many logs at the main application where the user run the VM.

The system tests is a single file called system-tests/system-tests.py

Why a single file ?
System tests are slow, we need to boot the machine only once, test everything in one go, in a organized way to make sure everything is workign in a single test pass. We are not allowed to make a system tests that takes a long time to run, just because our testing design is bad and repating same command at other tests (booting, waiting, finishing vm and etc). 
The test have two steps:
1 - first we need to validate an wrong password for the root disk, it is suppose to end the application, we boot the vm and it will fail fast, so no problem with the test time here.
2 - We boot the vm with correct password and do tests in order to ensure we do not need to boot the vm again for other tests.

Can we skip tests ?
Yes, we can create name for each testing step and skip a list of tests or pass a single test name to run (by default we run all test in a single pass).

Read on:

* **The runner is `system-tests/run.sh`** (`make system-tests`, `SYSTEM_TEST_ARGS` forwarded). It
  boots the machine once, sets `DESK_PLUGIN_PORT` for the plugin, starts the application with
  `--plugin-path`, and runs the steps in order. It never starts a second application to test
  something the first one could have shown.
* **One boot, one pass.** A step that needs a fresh boot is a step the project's rules got wrong; a step
  that is slow is a step repeating work an earlier step already did. A new step is added to the
  single pass, not as a new script that boots again.
* **Every step has a name, and that name is what `--only`/`--skip` take** (comma-separated), e.g.
  `system-tests.py --only boot-and-password --skip input`. `--list` prints the names. A skipped step
  is reported as skipped, and skipping everything must still exit 0.
* **Steps assert on events, not on a log or a file.** They subscribe to the plugin's `/ws`, call
  `/status`, `POST /frame` when the pixels matter, and answer `question` events. If a step needs a
  fact the plugin does not expose, the fix is a new hook in the plugin — a new
  print or a new file in the application is never the fix.
* **The application is driven only through its documented interface**: its switches, its keys
  (`--window-command f9`), the plugin, and the hypervisor's own process. A test does not `kill -9`
  the application unless it is testing exactly that, and it always collects the application's exit
  status.
* **Timing is the application's, not the test's.** The test waits for the guest's ready marker
  (`--ready-file`) and for events; sleeps are a last resort with a bounded, generous limit, and a
  test that needs many of them is comparing the guest's boot time, not the feature.
* **The passphrase is never stored.** The person running the test types it; the test passes it to
  the application through the plugin's `question`/`answer` — see "Environment variables".
* **A failed step prints what it saw** (the events, the status, the frame's path) so a failure does
  not need a second run to explain itself. Nothing is left behind: the test's own directory is
  scratch, and the application must not have written there.

The advantage of having a plugin that monitor/controls desktop-cracker is also the fact we can make the window invisible during the system tests, we do not need it to be visible to run the tests, visible windows may disturb the user so we avoid showing windows during the tests. Other dialogs we can just do untit tests mocking things and the final test is the user who does and give us feedback (that a small final testing called manual tests).

DO NOT EXPOSE DIALOGS DURING THE TESTS, we created the plugin to automate the dialogs, tests without plugin are only unit tests without dialogs.

If a dialog need to be tested ?
Do not test, the user is going to test and give feedback to you.

If the plugin is loaded, desktop-cracker will hide the main window by default during the run.