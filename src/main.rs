use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::fs::OpenOptions;
use std::io::Write;

const MASQUE_48: u64 = 0xFFFFFFFFFFFF;

#[derive(Copy, Clone, Debug)]
enum EngineType { StandardSha256, CustomFeistel, RobustInteracting }

#[derive(Copy, Clone, Debug)]
enum ComboType { Concatenation, XorSum, HashThenHash, Interacting, WidePipe }

struct BenchResult {
    duration: Duration,
    iterations: u64,
}

// --- ФУНКЦИИ СЖАТИЯ ---

fn compress(engine: EngineType, iv: &[u8], m: u64, target_bits: u32) -> (u64, Vec<u8>) {
    let mask = (1u64 << target_bits) - 1;
    match engine {
        EngineType::StandardSha256 => {
            let mut hasher = Sha256::new();
            hasher.update(iv);
            hasher.update(m.to_le_bytes());
            let res = hasher.finalize();
            let val = u64::from_be_bytes(res[0..8].try_into().unwrap());
            (val & mask, res.to_vec())
        }
        _ => {
            let state = u64::from_le_bytes(iv[0..8].try_into().unwrap()) & MASQUE_48;
            let mut h = state ^ (m.wrapping_mul(0xBF58476D1CE4E5B9));
            h = h.rotate_left(13).wrapping_add(0x94D049BB133111EB);
            (h & mask, h.to_le_bytes().to_vec())
        }
    }
}

fn combine_step(eng: EngineType, cmb: ComboType, iv1: &[u8], iv2: &[u8], m: u64, bits: u32) -> (u128, Vec<u8>, Vec<u8>) {
    match cmb {
        ComboType::Concatenation => {
            let (h1, v1) = compress(eng, iv1, m, bits);
            let (h2, v2) = compress(eng, iv2, m, bits);
            ((h1 as u128) << 64 | (h2 as u128), v1, v2)
        }
        ComboType::XorSum => {
            let (h1, v1) = compress(eng, iv1, m, bits);
            let (h2, v2) = compress(eng, iv2, m, bits);
            ((h1 ^ h2) as u128, v1, v2)
        }
        ComboType::HashThenHash => {
            let (_, v1) = compress(eng, iv1, m, 64);
            let (h2, v2) = compress(eng, &v1, m, bits);
            (h2 as u128, v1, v2)
        }
        ComboType::Interacting => {
            let (h1, mut v1) = compress(eng, iv1, m, 64);
            let (h2, mut v2) = compress(eng, iv2, m, 64);
            v1[0] = v1[0].wrapping_add(v2[1]);
            v2[0] = v2[0].wrapping_add(v1[1]);
            let mask = (1u64 << bits) - 1;
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
        ComboType::WidePipe => {
            let (h1, v1) = compress(eng, iv1, m, 64);
            ((h1 & ((1u64 << bits) - 1)) as u128, v1.clone(), v1)
        }
    }
}

// --- ЛОГИКА АТАК ---

fn attack_direct(eng: EngineType, cmb: ComboType, bits: u32) -> BenchResult {
    let start = Instant::now();
    let mut seen = HashMap::new();
    let (iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);
    for m in 0..5_000_000 {
        let (h, _, _) = combine_step(eng, cmb, &iv1, &iv2, m, bits);
        if seen.contains_key(&h) { return BenchResult { duration: start.elapsed(), iterations: m }; }
        seen.insert(h, m);
    }
    BenchResult { duration: start.elapsed(), iterations: 5_000_000 }
}

fn attack_joux(eng: EngineType, cmb: ComboType, bits: u32) -> BenchResult {
    let start = Instant::now();
    let (mut iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);
    let mut msgs = vec![vec![]];
    let mut total_iters = 0;

    for _ in 0..bits.min(10) {
        let mut seen = HashMap::new();
        let mut m = 0;
        let (m1, m2, next_iv) = loop {
            total_iters += 1;
            let (h, v1, _) = combine_step(eng, cmb, &iv1, &iv2, m, bits);
            let h1 = (h >> 64) as u64;
            if let Some(old_m) = seen.insert(h1, m) { break (old_m, m, v1); }
            m += 1; if m > 200_000 { break (0,0,v1); }
        };
        let mut next_gen = Vec::with_capacity(msgs.len() * 2);
        for list in msgs {
            let mut c1 = list.clone(); c1.push(m1); next_gen.push(c1);
            let mut c2 = list; c2.push(m2); next_gen.push(c2);
        }
        msgs = next_gen; iv1 = next_iv;
    }

    let mut seen_h2 = HashMap::new();
    for msg_list in msgs {
        total_iters += 1;
        let mut curr_iv2 = iv2.clone();
        for &m in &msg_list {
            let (_, _, v2) = combine_step(eng, cmb, &iv1, &curr_iv2, m, bits);
            curr_iv2 = v2;
        }
        if seen_h2.contains_key(&curr_iv2) { return BenchResult { duration: start.elapsed(), iterations: total_iters }; }
        seen_h2.insert(curr_iv2, ());
    }
    BenchResult { duration: start.elapsed(), iterations: total_iters }
}

// --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ВЫВОДА ---

fn log_and_print(file: &mut std::fs::File, message: &str) {
    println!("{}", message);
    if let Err(e) = writeln!(file, "{}", message) {
        eprintln!("Error writing to log file: {}", e);
    }
}

fn main() -> std::io::Result<()> {
    let bits = 14;
    let log_filename = "joux_attack_results.log";
    
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_filename)?;

    let engines = [EngineType::StandardSha256, EngineType::CustomFeistel, EngineType::RobustInteracting];
    let combos = [ComboType::Concatenation, ComboType::XorSum, ComboType::HashThenHash, ComboType::Interacting, ComboType::WidePipe];

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    log_and_print(&mut log_file, &format!("\n\n--- ЗАПУСК: {} ---", timestamp));
    log_and_print(&mut log_file, &format!("Целевые биты: {}\n", bits));

    // ТАБЛИЦА
    log_and_print(&mut log_file, "=== СВОДНАЯ ТАБЛИЦА ===");
    let header = format!("{:<18} | {:<15} | {:>10} | {:>10} | {:>10} | {:>8}", 
                         "Алгоритм", "Комбинация", "Dir Iter", "Joux Iter", "Dir ms", "Ratio");
    log_and_print(&mut log_file, &header);
    log_and_print(&mut log_file, &"-".repeat(95));

    let mut data_points = Vec::new();

    for eng in &engines {
        for cmb in &combos {
            let d = attack_direct(*eng, *cmb, bits);
            let j = attack_joux(*eng, *cmb, bits);
            
            let d_ms = d.duration.as_secs_f64() * 1000.0;
            let j_ms = j.duration.as_secs_f64() * 1000.0;
            let ratio = if j.iterations > 0 { d.iterations as f64 / j.iterations as f64 } else { 0.0 };

            let row = format!(
                "{:<18?} | {:<15?} | {:>10} | {:>10} | {:>10.2} | {:>8.2}x", 
                eng, cmb, d.iterations, j.iterations, d_ms, ratio
            );
            log_and_print(&mut log_file, &row);
            
            data_points.push((*eng, *cmb, d_ms, d.iterations, j_ms, j.iterations, ratio));
        }
        log_and_print(&mut log_file, &"-".repeat(95));
    }

    // ДЕТАЛЬНЫЙ ЛОГ
    log_and_print(&mut log_file, "\n\n=== ДЕТАЛЬНЫЙ ЛОГ ДАННЫХ ===");

    for (eng, cmb, d_ms, d_iter, j_ms, j_iter, ratio) in data_points {
        log_and_print(&mut log_file, "RESULT_START");
        log_and_print(&mut log_file, &format!("Engine            : {:?}", eng));
        log_and_print(&mut log_file, &format!("Combination       : {:?}", cmb));
        log_and_print(&mut log_file, &format!("Direct_Time_ms    : {:.4}", d_ms));
        log_and_print(&mut log_file, &format!("Direct_Iterations : {}", d_iter));
        log_and_print(&mut log_file, &format!("Joux_Time_ms      : {:.4}", j_ms));
        log_and_print(&mut log_file, &format!("Joux_Iterations   : {}", j_iter));
        log_and_print(&mut log_file, &format!("Efficiency_Ratio  : {:.2}x", ratio));
        log_and_print(&mut log_file, "RESULT_END");
        log_and_print(&mut log_file, "------------------------------");
    }

    println!("\n[INFO] Результаты добавлены в файл {}", log_filename);
    Ok(())
}