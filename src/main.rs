use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;

// --- DYNAMIC LIMITS CONFIGURATION ---

struct AttackParams {
    direct_limit: u64,
    direct_memory_cap: usize,
    joux_inner_limit: u64,
    joux_levels: u32,
}

impl AttackParams {
    fn new(bits: u32) -> Self {
        let total_bits = bits * 2;
        
        // Математическое ожидание коллизии для Birthday Attack: 1.25 * 2^(total_bits/2)
        // Для 26 бит (52 итого) это ~83 млн итераций.
        let expected_direct = (1.25 * 2.0f64.powf(total_bits as f64 / 2.0)) as u64;

        // Лимит памяти для HashMap. 
        // 100 млн записей u128/u64 — это ~3.5-4 ГБ ОЗУ. 
        // Это безопасно для ПК с 8-16 ГБ оперативной памяти.
        let mem_cap = 100_000_000; 

        Self {
            // Ставим лимит в 4 раза больше ожидаемого, чтобы точно «поймать» коллизию,
            // даже если нам очень не везет со статистикой.
            direct_limit: expected_direct * 4, 
            
            direct_memory_cap: mem_cap,
            
            // Для атаки Жу: ищем коллизию в одной трубе (2^bits).
            // Ожидание для 26 бит — 1.25 * 2^13 ≈ 10 000 итераций.
            joux_inner_limit: 1_000_000, 
            
            // 12-14 этажей мультиколлизий дадут достаточно вариантов (2^12 = 4096),
            // чтобы во второй трубе коллизия нашлась почти мгновенно.
            joux_levels: (bits / 2).clamp(10, 14), 
        }
    }
}

// --- ТИПЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ОСТАЮТСЯ БЕЗ ИЗМЕНЕНИЙ) ---

#[derive(Copy, Clone, Debug)]
enum EngineType { StandardSha256, CustomFeistel, Sha256PlusFeistel, FeistelPlusSha256 }

#[derive(Copy, Clone, Debug)]
enum ComboType { Concatenation, XorSum, HashThenHash, Interacting, WidePipe, RobustInteraction }

struct BenchResult { iterations: u64 }

fn feistel_round(x: u32, key: u32) -> u32 {
    let mut h = x.wrapping_add(key);
    h ^= h.rotate_left(13);
    let non_linear = (h & 0x55555555) ^ (!h & 0xAAAAAAAA);
    h = h.wrapping_mul(0xBF58476D);
    h ^ non_linear
}

fn base_compress(engine: EngineType, iv: &[u8], m: u64, target_bits: u32) -> (u64, Vec<u8>) {
    let mask = if target_bits >= 64 { !0u64 } else { (1u64 << target_bits) - 1 };
    match engine {
        EngineType::StandardSha256 | EngineType::Sha256PlusFeistel => {
            let mut hasher = Sha256::new();
            hasher.update(iv);
            hasher.update(m.to_le_bytes());
            let res = hasher.finalize();
            let val = u64::from_le_bytes(res[0..8].try_into().unwrap());
            ((val ^ m) & mask, res.to_vec())
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
            ((h ^ m) & mask, h.to_le_bytes().to_vec())
        }
    }
}

fn combine_step(eng: EngineType, cmb: ComboType, iv1: &[u8], iv2: &[u8], m: u64, bits: u32) -> (u128, Vec<u8>, Vec<u8>) {
    let mask = (1u64 << bits) - 1;
    let (p1_sha, p2_sha) = match eng {
        EngineType::StandardSha256 => (true, true),
        EngineType::CustomFeistel => (false, false),
        EngineType::Sha256PlusFeistel => (true, false),
        EngineType::FeistelPlusSha256 => (false, true),
    };
    match cmb {
        ComboType::Concatenation => {
            let (h1, v1) = base_compress(if p1_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv1, m, bits);
            let (h2, v2) = base_compress(if p2_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv2, m, bits);
            (((h1 as u128) << 64) | (h2 as u128), v1, v2)
        }
        ComboType::XorSum => {
            let (h1, v1) = base_compress(if p1_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv1, m, bits);
            let (h2, v2) = base_compress(if p2_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv2, m, bits);
            ((h1 ^ h2) as u128, v1, v2)
        }
        ComboType::HashThenHash => {
            let (_, v1) = base_compress(if p1_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv1, m, bits);
            let (h2, v2) = base_compress(if p2_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, &v1, m, bits);
            ((h2 as u128) << 64, v1, v2)
        }
        ComboType::Interacting => {
            let (h1, v1) = base_compress(if p1_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv1, m, bits);
            let (h2, v2) = base_compress(if p2_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, &v1, m, bits);
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
        ComboType::WidePipe => {
            let (h_w, v_w) = base_compress(if p1_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv1, m, 64);
            let fh = h_w & mask;
            ( ((fh as u128) << 64) | (fh as u128), v_w.clone(), v_w)
        }
        ComboType::RobustInteraction => {
            let (h1, v1) = base_compress(if p1_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv1, m, bits);
            let (h2, v2) = base_compress(if p2_sha { EngineType::StandardSha256 } else { EngineType::CustomFeistel }, iv2, m ^ h1, bits);
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
    }
}

// --- ATTACKS WITH DYNAMIC PARAMS ---

fn attack_direct(eng: EngineType, cmb: ComboType, bits: u32, params: &AttackParams) -> BenchResult {
    let mut seen = HashMap::with_capacity(params.direct_memory_cap.min(1_000_000));
    let (iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);

    for m in 0..params.direct_limit {
        let (h, _, _) = combine_step(eng, cmb, &iv1, &iv2, m, bits);
        if seen.contains_key(&h) { return BenchResult { iterations: m }; }
        
        // Защита памяти
        if m < params.direct_memory_cap as u64 {
            seen.insert(h, m);
        }
    }
    BenchResult { iterations: params.direct_limit }
}

fn attack_joux(eng: EngineType, cmb: ComboType, bits: u32, params: &AttackParams) -> BenchResult {
    let (mut iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);
    let mut msgs = vec![vec![]];
    let mut total_iters = 0;

    for _ in 0..params.joux_levels {
        let mut seen = HashMap::with_capacity(10000);
        let mut m = 0;
        let (m1, m2, next_iv) = loop {
            total_iters += 1;
            let (h, v1, _) = combine_step(eng, cmb, &iv1, &iv2, m, bits);
            let h1 = (h >> 64) as u64;
            if let Some(&old_m) = seen.get(&h1) { break (old_m, m, v1); }
            seen.insert(h1, m);
            m += 1; 
            if m > params.joux_inner_limit { break (0,0,v1); }
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
        if seen_h2.contains_key(&curr_iv2) { return BenchResult { iterations: total_iters }; }
        seen_h2.insert(curr_iv2, ());
    }
    BenchResult { iterations: total_iters }
}

// --- MAIN ---

fn log_and_print(file: &mut std::fs::File, message: &str) {
    println!("{}", message);
    let _ = writeln!(file, "{}", message);
}

fn main() -> std::io::Result<()> {
    // Определяем диапазон исследования: от 14 до 26 бит с шагом 2
    let bit_range = (14..=26).step_by(2);
    
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("dynamic_joux_results.log")?;

    let engines = [
        EngineType::StandardSha256, 
        EngineType::CustomFeistel, 
        EngineType::Sha256PlusFeistel, 
        EngineType::FeistelPlusSha256
    ];
    
    let combos = [
        ComboType::Concatenation, 
        ComboType::XorSum, 
        ComboType::HashThenHash, 
        ComboType::Interacting, 
        ComboType::WidePipe, 
        ComboType::RobustInteraction
    ];

    for bits in bit_range {
        let params = AttackParams::new(bits);
        
        log_and_print(&mut log_file, &format!("\n--- TEST ROUND: bits={} | Direct Limit={} | Joux Levels={} ---", 
            bits, params.direct_limit, params.joux_levels));
        
        log_and_print(&mut log_file, &format!("{:<20} | {:<17} | {:>10} | {:>10} | {:>8}", 
            "Algorithm Pair", "Combination", "Dir Iter", "Joux Iter", "Ratio"));
        
        for eng in &engines {
            for cmb in &combos {
                let d = attack_direct(*eng, *cmb, bits, &params);
                let j = attack_joux(*eng, *cmb, bits, &params);
                
                let ratio = if j.iterations > 0 { 
                    d.iterations as f64 / j.iterations as f64 
                } else { 
                    0.0 
                };

                log_and_print(&mut log_file, &format!("{:<20?} | {:<17?} | {:>10} | {:>10} | {:>8.2}x", 
                    eng, cmb, d.iterations, j.iterations, ratio));
            }
        }
        
        log_and_print(&mut log_file, &format!("--- END OF ROUND bits={} ---\n", bits));
    }

    Ok(())
}