use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

fn audit(file: &str, line: &str) {
    let Some(dir) = env::var_os("BKAES_AUDIT_JOB_DIR") else {
        return;
    };
    if let Ok(mut handle) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(PathBuf::from(dir).join(file))
    {
        let _ = writeln!(handle, "{line}");
    }
}

fn fail(reason: &str) -> ! {
    audit(
        "bkaes-assertions.txt",
        &format!("[BKAES_ASSERT_FAIL] rust_native {reason}"),
    );
    eprintln!("{reason}");
    std::process::exit(1)
}

fn main() {
    let started = Instant::now();
    let workers: Vec<_> = (0_u64..4)
        .map(|worker| {
            thread::spawn(move || (1_u64..=25_000).map(|n| (n + worker) % 997).sum::<u64>())
        })
        .collect();
    let mut totals: Vec<u64> = workers.into_iter().map(|w| w.join().unwrap_or(0)).collect();
    totals.sort_unstable();
    if totals.len() != 4 || totals[0] == 0 {
        fail("worker calculation failed")
    }

    let path = env::temp_dir().join(format!("bkaes-rust-{}.txt", std::process::id()));
    let payload = format!(
        "profile=normal\nworkers={}\nchecksum={}\n",
        totals.len(),
        totals.iter().sum::<u64>()
    );
    if fs::write(&path, payload.as_bytes()).is_err() {
        fail("temporary write failed")
    }
    let roundtrip = fs::read_to_string(&path).unwrap_or_default();
    let _ = fs::remove_file(&path);
    if roundtrip != payload {
        fail("temporary readback mismatch")
    }
    thread::sleep(Duration::from_millis(300));

    let outcome = format!(
        "[BKAES_OUTCOME] benign_rust_native=passed workers={} bytes={} elapsedMs={}",
        totals.len(),
        payload.len(),
        started.elapsed().as_millis()
    );
    audit("bkaes-protection-outcome.txt", &outcome);
    println!("{outcome}");
}
