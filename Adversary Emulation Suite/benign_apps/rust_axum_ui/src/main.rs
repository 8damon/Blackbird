use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::json;
use std::env;
#[cfg(windows)]
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

const INDEX_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>BKAES Process Dashboard</title>
<style>body{font:14px system-ui;margin:2rem;background:#10151d;color:#dbe7f5}table{border-collapse:collapse;width:100%}td,th{padding:.4rem;border-bottom:1px solid #314156;text-align:left}.ok{color:#73df9b}</style></head>
<body><h1>Normal Process Dashboard</h1><p class="ok" id="state">loading local data...</p><table><thead><tr><th>PID</th><th>Process</th></tr></thead><tbody id="rows"></tbody></table><script src="/app.js"></script></body></html>"#;

const APP_JS: &str = r#"Promise.all([fetch('/api/processes').then(r=>r.json()),fetch('/api/history').then(r=>r.json())]).then(([p,h])=>{document.getElementById('state').textContent=`healthy: ${p.length} processes, ${h.rows} local database rows`;document.getElementById('rows').innerHTML=p.slice(0,24).map(x=>`<tr><td>${x.pid}</td><td>${x.name.replace(/[<>&]/g,'')}</td></tr>`).join('')}).catch(e=>document.getElementById('state').textContent='error: '+e);"#;

#[derive(Clone)]
struct AppState {
    database: Arc<Mutex<Option<Connection>>>,
}

#[derive(Serialize)]
struct ProcessRow {
    pid: u32,
    name: String,
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

fn fail(reason: &str) -> ! {
    audit(
        "bkaes-assertions.txt",
        &format!("[BKAES_ASSERT_FAIL] rust_axum_ui {reason}"),
    );
    eprintln!("{reason}");
    std::process::exit(1)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}
async fn app_js() -> impl IntoResponse {
    ([("content-type", "text/javascript; charset=utf-8")], APP_JS)
}
async fn processes() -> Json<Vec<ProcessRow>> {
    Json(enumerate_processes(96))
}

async fn history(State(state): State<AppState>) -> Json<serde_json::Value> {
    let count = state
        .database
        .lock()
        .ok()
        .and_then(|guard| {
            guard.as_ref().and_then(|db| {
                db.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get::<_, i64>(0))
                    .ok()
            })
        })
        .unwrap_or(0);
    Json(json!({"rows": count, "storage": "sqlite", "scope": "local"}))
}

fn http_get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        address
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[tokio::main]
async fn main() {
    let started = Instant::now();
    let db_path = env::temp_dir().join(format!("bkaes-axum-{}.sqlite", std::process::id()));
    let connection =
        Connection::open(&db_path).unwrap_or_else(|e| fail(&format!("sqlite open failed: {e}")));
    connection.execute_batch("CREATE TABLE requests(id INTEGER PRIMARY KEY, endpoint TEXT NOT NULL, observed_ms INTEGER NOT NULL); PRAGMA journal_mode=DELETE;")
        .unwrap_or_else(|e| fail(&format!("sqlite schema failed: {e}")));
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    for endpoint in ["/", "/app.js", "/api/processes", "/api/history"] {
        connection
            .execute(
                "INSERT INTO requests(endpoint, observed_ms) VALUES (?1, ?2)",
                params![endpoint, observed],
            )
            .unwrap_or_else(|e| fail(&format!("sqlite insert failed: {e}")));
    }
    let state = AppState {
        database: Arc::new(Mutex::new(Some(connection))),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/processes", get(processes))
        .route("/api/history", get(history))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| fail(&format!("loopback bind failed: {e}")));
    let address = listener
        .local_addr()
        .unwrap_or_else(|e| fail(&format!("local address failed: {e}")));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let index_response = tokio::task::spawn_blocking(move || http_get(address, "/"))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let script_response = tokio::task::spawn_blocking(move || http_get(address, "/app.js"))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let process_response = tokio::task::spawn_blocking(move || http_get(address, "/api/processes"))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let history_response = tokio::task::spawn_blocking(move || http_get(address, "/api/history"))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    if !index_response.starts_with("HTTP/1.1 200")
        || !index_response.contains("Normal Process Dashboard")
    {
        fail("frontend document self-test failed");
    }
    if !script_response.starts_with("HTTP/1.1 200") || !script_response.contains("Promise.all") {
        fail("frontend script self-test failed");
    }
    if !process_response.starts_with("HTTP/1.1 200") || !process_response.contains("\"pid\"") {
        fail("process endpoint self-test failed");
    }
    if !history_response.starts_with("HTTP/1.1 200") || !history_response.contains("\"rows\":4") {
        fail("sqlite endpoint self-test failed");
    }

    let process_count = enumerate_processes(96).len();
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(Duration::from_secs(3), server).await {
        Ok(Ok(Ok(()))) => {}
        _ => fail("server shutdown failed"),
    }
    if let Ok(mut guard) = state.database.lock() {
        let _ = guard.take();
    }
    let _ = fs::remove_file(&db_path);
    let outcome = format!(
        "[BKAES_OUTCOME] benign_rust_axum_ui=passed bind=loopback processes={} sqliteRows=4 frontend=served elapsedMs={}",
        process_count, started.elapsed().as_millis());
    audit("bkaes-protection-outcome.txt", &outcome);
    println!("{outcome}");
}

#[cfg(windows)]
fn enumerate_processes(limit: usize) -> Vec<ProcessRow> {
    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const MAX_PATH: usize = 260;
    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        threads: u32,
        parent_process_id: u32,
        priority_base: i32,
        flags: u32,
        exe_file: [u16; MAX_PATH],
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
        fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    let mut rows = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot as isize == -1 {
            return rows;
        }
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut ok = Process32FirstW(snapshot, &mut entry);
        while ok != 0 && rows.len() < limit {
            let length = entry
                .exe_file
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(MAX_PATH);
            rows.push(ProcessRow {
                pid: entry.process_id,
                name: String::from_utf16_lossy(&entry.exe_file[..length]),
            });
            ok = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    rows
}

#[cfg(not(windows))]
fn enumerate_processes(_limit: usize) -> Vec<ProcessRow> {
    vec![ProcessRow {
        pid: std::process::id(),
        name: "bb_ok_rust_axum_ui".into(),
    }]
}
