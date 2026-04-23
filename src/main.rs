use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Copy, Clone, Debug)]
enum EngineType { 
    StandardSha256, 
    CustomFeistel,
    Sha256PlusFeistel, // H1 = SHA256, H2 = Feistel
    FeistelPlusSha256  // H1 = Feistel, H2 = SHA256
}

#[derive(Copy, Clone, Debug)]
enum ComboType { Concatenation, XorSum, HashThenHash, Interacting, WidePipe, RobustInteraction }

struct BenchResult {
    iterations: u64,
}

// --- NON-LINEAR FEISTEL HELPER ---

fn feistel_round(x: u32, key: u32) -> u32 {
    let mut h = x.wrapping_add(key);
    h ^= h.rotate_left(13);
    let non_linear = (h & 0x55555555) ^ (!h & 0xAAAAAAAA);
    h = h.wrapping_mul(0xBF58476D);
    h ^ non_linear
}

// --- BASE ENGINES (Internal helper) ---

fn base_compress(engine: EngineType, iv: &[u8], m: u64, target_bits: u32) -> (u64, Vec<u8>) {
    let mask = (1u64 << target_bits) - 1;
    match engine {
        EngineType::StandardSha256 | EngineType::Sha256PlusFeistel if true => {
            // Вспомогательная логика выбора движка вынесена в combine_step, 
            // здесь определяем только конкретную реализацию
            let mut hasher = Sha256::new();
            hasher.update(iv);
            hasher.update(m.to_le_bytes());
            let res = hasher.finalize();
            let val = u64::from_be_bytes(res[0..8].try_into().unwrap());
            (val & mask, res.to_vec())
        }
        _ => {
            let state = u64::from_le_bytes(iv[0..8].try_into().unwrap());
            let mut left = (state >> 32) as u32;
            let mut right = (state & 0xFFFFFFFF) as u32;
            let msg_part = (m & 0xFFFFFFFF) as u32;

            for i in 0..4 {
                let temp = right;
                right = left ^ feistel_round(right, msg_part.wrapping_add(i));
                left = temp;
            }

            let h = ((left as u64) << 32) | (right as u64);
            (h & mask, h.to_le_bytes().to_vec())
        }
    }
}

// Универсальная обертка для сжатия
fn compress_specific(is_sha: bool, iv: &[u8], m: u64, target_bits: u32) -> (u64, Vec<u8>) {
    if is_sha {
        base_compress(EngineType::StandardSha256, iv, m, target_bits)
    } else {
        base_compress(EngineType::CustomFeistel, iv, m, target_bits)
    }
}

// --- COMBINATION STEP ---

fn combine_step(eng: EngineType, cmb: ComboType, iv1: &[u8], iv2: &[u8], m: u64, bits: u32) -> (u128, Vec<u8>, Vec<u8>) {
    // Определяем, какой движок идет в какую трубу
    let (pipe1_is_sha, pipe2_is_sha) = match eng {
        EngineType::StandardSha256 => (true, true),
        EngineType::CustomFeistel  => (false, false),
        EngineType::Sha256PlusFeistel => (true, false),
        EngineType::FeistelPlusSha256 => (false, true),
    };

    match cmb {
        ComboType::Concatenation => {
            let (h1, v1) = compress_specific(pipe1_is_sha, iv1, m, bits);
            let (h2, v2) = compress_specific(pipe2_is_sha, iv2, m, bits);
            ((h1 as u128) << 64 | (h2 as u128), v1, v2)
        }
        ComboType::XorSum => {
            let (h1, v1) = compress_specific(pipe1_is_sha, iv1, m, bits);
            let (h2, v2) = compress_specific(pipe2_is_sha, iv2, m, bits);
            ((h1 ^ h2) as u128, v1, v2)
        }
        ComboType::HashThenHash => {
            // Результат первой трубы становится IV для второй
            let (_, v1) = compress_specific(pipe1_is_sha, iv1, m, 64);
            let (h2, v2) = compress_specific(pipe2_is_sha, &v1, m, bits);
            (h2 as u128, v1, v2)
        }
        ComboType::Interacting => {
            let (h1, mut v1) = compress_specific(pipe1_is_sha, iv1, m, 64);
            let (h2, mut v2) = compress_specific(pipe2_is_sha, iv2, m, 64);
            // Смешивание состояний
            v1[0] = v1[0].wrapping_add(v2[1]);
            v2[0] = v2[0].wrapping_add(v1[1]);
            let mask = (1u64 << bits) - 1;
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
        ComboType::WidePipe => {
            // Для WidePipe используем только первую выбранную функцию, но с широким состоянием
            let (h1, v1) = compress_specific(pipe1_is_sha, iv1, m, 64);
            let mask = (1u64 << bits) - 1;
            ((h1 & mask) as u128, v1.clone(), v1)
        }
        ComboType::RobustInteraction => {
            let (h1, mut v1) = compress_specific(pipe1_is_sha, iv1, m, 64);
            let (h2, mut v2) = compress_specific(pipe2_is_sha, iv2, m, 64);
            for i in 0..v1.len().min(v2.len()) {
                v1[i] = v1[i].wrapping_add(v2[i]).rotate_left(3);
                v2[i] = (v2[i] ^ v1[i]).rotate_right(3);
            }
            let mask = (1u64 << bits) - 1;
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
    }
}

// --- ATTACK LOGIC ---

fn attack_direct(eng: EngineType, cmb: ComboType, bits: u32) -> BenchResult {
    let mut seen = HashMap::new();
    let (iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);
    for m in 0..5_000_000 {
        let (h, _, _) = combine_step(eng, cmb, &iv1, &iv2, m, bits);
        if seen.contains_key(&h) { 
            return BenchResult { iterations: m }; 
        }
        seen.insert(h, m);
    }
    BenchResult { iterations: 5_000_000 }
}

fn attack_joux(eng: EngineType, cmb: ComboType, bits: u32) -> BenchResult {
    let (mut iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);
    let mut msgs = vec![vec![]];
    let mut total_iters = 0;

    // Фаза 1: Поиск мультиколлизий в первой трубе
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

    // Фаза 2: Проверка во второй трубе
    let mut seen_h2 = HashMap::new();
    for msg_list in msgs {
        total_iters += 1;
        let mut curr_iv2 = iv2.clone();
        for &m in &msg_list {
            let (_, _, v2) = combine_step(eng, cmb, &iv1, &curr_iv2, m, bits);
            curr_iv2 = v2;
        }
        if seen_h2.contains_key(&curr_iv2) { 
            return BenchResult { iterations: total_iters }; 
        }
        seen_h2.insert(curr_iv2, ());
    }
    BenchResult { iterations: total_iters }
}

fn log_and_print(file: &mut std::fs::File, message: &str) {
    println!("{}", message);
    let _ = writeln!(file, "{}", message);
}

fn main() -> std::io::Result<()> {
    let bits = 14;
    let log_filename = "joux_attack_results.log";
    let mut log_file = OpenOptions::new().create(true).append(true).open(log_filename)?;

    let engines = [
        EngineType::StandardSha256, 
        EngineType::CustomFeistel,
        EngineType::Sha256PlusFeistel,
        EngineType::FeistelPlusSha256
    ];
    let combos = [
        ComboType::Concatenation, ComboType::XorSum, ComboType::HashThenHash, 
        ComboType::Interacting, ComboType::WidePipe, ComboType::RobustInteraction
    ];

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    log_and_print(&mut log_file, &format!("\n--- BENCHMARK START: {} ---", timestamp));

    log_and_print(&mut log_file, &format!("{:<20} | {:<17} | {:>10} | {:>10} | {:>8}", 
                         "Algorithm Pair", "Combination", "Dir Iter", "Joux Iter", "Ratio"));
    log_and_print(&mut log_file, &"-".repeat(80));

    for eng in &engines {
        for cmb in &combos {
            let d = attack_direct(*eng, *cmb, bits);
            let j = attack_joux(*eng, *cmb, bits);
            let ratio = if j.iterations > 0 { d.iterations as f64 / j.iterations as f64 } else { 0.0 };
            log_and_print(&mut log_file, &format!(
                "{:<20?} | {:<17?} | {:>10} | {:>10} | {:>8.2}x", 
                eng, cmb, d.iterations, j.iterations, ratio
            ));
        }
        log_and_print(&mut log_file, &"-".repeat(80));
    }
    Ok(())
}