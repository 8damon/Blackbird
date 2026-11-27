use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tauri::Manager;

struct AppState {
    calculation_complete: Arc<AtomicBool>,
}

#[tauri::command]
fn calculate(state: tauri::State<'_, AppState>, hours: f64, rate: f64) -> f64 {
    let result = (hours * rate * 100.0).round() / 100.0;
    if hours == 7.0 && rate == 42.0 && result == 294.0 {
        state.calculation_complete.store(true, Ordering::Release);
    }
    result
}

fn audit(file: &str, line: &str) {
    let Some(dir) = env::var_os("BKAES_AUDIT_JOB_DIR") else {
        return;
    };
    if let Ok(mut output) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(PathBuf::from(dir).join(file))
    {
        let _ = writeln!(output, "{line}");
    }
}

fn main() {
    let setup_complete = Arc::new(AtomicBool::new(false));
    let calculation_complete = Arc::new(AtomicBool::new(false));
    let setup_watchdog = Arc::clone(&setup_complete);
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(10));
        if !setup_watchdog.load(Ordering::Acquire) {
            audit(
                "bkaes-assertions.txt",
                "[BKAES_ASSERT_FAIL] tauri_ui setup callback timed out; an interactive desktop is required",
            );
            std::process::exit(2);
        }
    });

    tauri::Builder::default()
        .manage(AppState { calculation_complete })
        .invoke_handler(tauri::generate_handler![calculate])
        .setup(move |app| {
            setup_complete.store(true, Ordering::Release);
            let calculation_observed = Arc::clone(&app.state::<AppState>().calculation_complete);
            let settings = env::temp_dir().join(format!("bkaes-tauri-{}.json", std::process::id()));
            fs::write(&settings, b"{\"theme\":\"system\",\"currency\":\"AUD\"}\n")?;
            let roundtrip = fs::read_to_string(&settings)?;
            let _ = fs::remove_file(&settings);
            if !roundtrip.contains("AUD") {
                audit("bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] tauri_ui settings roundtrip failed");
                return Err("settings roundtrip failed".into());
            }
            let handle = app.handle().clone();
            thread::spawn(move || {
                for _ in 0..80 {
                    if calculation_observed.load(Ordering::Acquire) {
                        audit("bkaes-protection-outcome.txt",
                              "[BKAES_OUTCOME] benign_tauri_ui=passed calculation=294 settings=roundtrip webview=created");
                        handle.exit(0);
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                audit("bkaes-assertions.txt",
                      "[BKAES_ASSERT_FAIL] tauri_ui frontend calculation was not observed");
                handle.exit(3);
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| {
            audit("bkaes-assertions.txt", &format!("[BKAES_ASSERT_FAIL] tauri_ui runtime failed: {error}"));
            std::process::exit(1);
        });
}
