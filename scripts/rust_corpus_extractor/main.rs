// Fingerprint-extraction Rust binary — exercises a broad slice of
// std APIs so the resulting binary contains many concrete std-fn
// instantiations whose TEEF goes into the corpus.
use std::collections::{HashMap, BTreeMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Read, Write, BufRead, BufReader, BufWriter, Cursor};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicUsize, Ordering}};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::env;
use std::process;

fn main() {
    let argv: Vec<String> = env::args().collect();
    let n = argv.len();
    let mut h: HashMap<String, Vec<u32>> = HashMap::new();
    h.insert("a".into(), (0..n as u32).collect());
    let _: Vec<_> = h.iter().filter(|(k,_)| !k.is_empty()).collect();
    let bm: BTreeMap<i64, String> = (0..16).map(|i| (i, format!("v{}", i))).collect();
    let _ = bm.range(1..10).count();
    let mut vd: VecDeque<u8> = VecDeque::with_capacity(64);
    for i in 0..32 { vd.push_back(i); }
    while let Some(_) = vd.pop_front() {}
    let s: HashSet<&str> = ["a","b","c"].iter().copied().collect();
    let _ = s.contains("a");
    let _ = s.iter().count();

    // String / formatting
    let mut buf = String::with_capacity(128);
    use std::fmt::Write as _;
    write!(buf, "argc={} time={:?}", n, Instant::now()).unwrap();
    let _ = buf.split('=').count();
    let _ = buf.to_uppercase().to_lowercase();
    let _ = buf.replace("=", " : ");
    let _ = format!("{:08x} {} {}", 0xdeadu32, std::f64::consts::PI, true);

    // io
    let mut sink = Vec::new();
    {
        let mut bw = BufWriter::new(&mut sink);
        for line in &["one","two","three"] {
            let _ = writeln!(bw, "{}", line);
        }
        let _ = bw.flush();
    }
    let cur = Cursor::new(&sink);
    let br = BufReader::new(cur);
    let _: Vec<_> = br.lines().collect();
    let _ = io::sink().write(b"hello").unwrap_or(0);

    // fs
    let _ = PathBuf::from("/tmp").join("doesnotexist").to_string_lossy().to_string();
    let _ = fs::metadata("/etc/hostname");
    let _ = env::current_dir();

    // sync / threading
    let counter = Arc::new(AtomicUsize::new(0));
    let mtx = Arc::new(Mutex::new(0u64));
    let rwl = Arc::new(RwLock::new(0u64));
    let (tx, rx) = mpsc::channel::<u32>();
    let mut handles = vec![];
    for i in 0..4 {
        let c = counter.clone();
        let m = mtx.clone();
        let r = rwl.clone();
        let txc = tx.clone();
        handles.push(thread::spawn(move || {
            c.fetch_add(1, Ordering::SeqCst);
            *m.lock().unwrap() += 1;
            *r.write().unwrap() += 1;
            let _ = txc.send(i);
            thread::sleep(Duration::from_millis(0));
        }));
    }
    drop(tx);
    while let Ok(_) = rx.recv() {}
    for h in handles { let _ = h.join(); }

    // Numeric / iter combinators
    let v: Vec<i64> = (0..1000).collect();
    let _ = v.iter().sum::<i64>();
    let _ = v.iter().filter(|x| *x % 2 == 0).count();
    let _ = v.iter().fold(0i64, |a, b| a.wrapping_add(*b));
    let _ = v.iter().enumerate().map(|(i,x)| i as i64 + *x).collect::<Vec<_>>();
    let mut v2 = v.clone();
    v2.sort();
    v2.reverse();
    v2.dedup();
    let _ = v2.binary_search(&500);

    // panic + Result + Option
    let r: Result<i32, &str> = Err("nope");
    let _ = r.unwrap_or(0);
    let opt: Option<i32> = Some(42);
    let _ = opt.map(|x| x * 2).unwrap_or_default();

    // Exit cleanly
    process::exit(0);
}
