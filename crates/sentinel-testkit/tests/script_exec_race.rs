//! Regression test for the "Text file busy" race in the fake-`ssh` helpers.
//!
//! Many gateway tests write a script and execute it at once, on several threads. When the test process itself opened
//! the script for writing, a `fork` on another thread could carry that descriptor into its child, and on Linux the
//! `execve` of the script then failed with ETXTBSY for as long as the child had not reached its own `exec`. CI used to
//! hide this by running every test binary on one thread. `write_executable` removes the cause; this test would fail
//! within a few hundred iterations on Linux if a helper went back to writing the script in-process.

use std::process::Command;

use sentinel_testkit::configs::{fake_ssh_script, raw_ssh_script};

const THREADS: usize = 8;
const ROUNDS: usize = 150;

#[test]
fn a_script_runs_at_once_while_other_threads_fork() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let dir = dir.path();
            scope.spawn(move || {
                for i in 0..ROUNDS {
                    let script = if i % 2 == 0 {
                        fake_ssh_script(dir, &format!("fake-{t}-{i}"), "exit 0")
                    } else {
                        raw_ssh_script(dir, &format!("raw-{t}-{i}"), "exit 0")
                    };
                    let status = Command::new(&script)
                        .status()
                        .unwrap_or_else(|e| panic!("exec {} (thread {t}, round {i}): {e}", script.display()));
                    assert!(status.success(), "{} exited with {status}", script.display());
                }
            });
        }
    });
}

#[test]
fn scripts_are_owner_only_and_hold_the_given_body() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = raw_ssh_script(dir.path(), "raw", "echo raw-body");
    assert_eq!(std::fs::metadata(&raw).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::read_to_string(&raw).unwrap(), "#!/bin/sh\necho raw-body\n");
    let out = Command::new(&raw).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "raw-body\n");

    let fake = fake_ssh_script(dir.path(), "fake", "echo fake-body");
    assert_eq!(std::fs::metadata(&fake).unwrap().permissions().mode() & 0o777, 0o700);
    let text = std::fs::read_to_string(&fake).unwrap();
    assert!(
        text.starts_with("#!/bin/sh\n") && text.contains("exec /usr/bin/ssh") && text.ends_with("echo fake-body\n"),
        "{text}"
    );
}
