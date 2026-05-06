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
        // Ожидание Birthday Attack для 26 бит (52 итого) ≈ 83 млн.
        let expected_direct = (1.25 * 2.0f64.powf(total_bits as f64 / 2.0)) as u64;
        let mem_cap = 100_000_000; 

        Self {
            direct_limit: expected_direct * 4, 
            direct_memory_cap: mem_cap,
            joux_inner_limit: 1_000_000, 
            joux_levels: (bits / 2).clamp(10, 14), 
        }
    }
}

// --- CORE CRYPTO ENGINE (BY COLLEAGUE) ---

fn base_compress(iv: &[u8], m: u64, target_bits: u32) -> (u64, Vec<u8>) {
    let mask = if target_bits >= 64 { !0u64 } else { (1u64 << target_bits) - 1 };

    let mut iv_padded = [0u8; 32];
    let len = iv.len().min(32);
    iv_padded[..len].copy_from_slice(&iv[..len]);

    let mut input = [0u8; 40];
    input[..8].copy_from_slice(&m.to_le_bytes());
    input[8..40].copy_from_slice(&iv_padded);

    let hash: [u8; 32] = Sha256::digest(&input).into();
    
    // Davies-Meyer: E(m, H) XOR H
    let e = u64::from_be_bytes(hash[..8].try_into().unwrap());
    let s = u64::from_le_bytes(iv_padded[..8].try_into().unwrap());

    let result = (e ^ s) & mask;
    (result, result.to_le_bytes().to_vec())
}

// --- COMBINERS LOGIC ---

#[derive(Copy, Clone, Debug)]
enum ComboType { Concatenation, XorSum, HashThenHash, Interacting, WidePipe, RobustInteraction }

fn combine_step(cmb: ComboType, iv1: &[u8], iv2: &[u8], m: u64, bits: u32) -> (u128, Vec<u8>, Vec<u8>) {
    let mask = (1u64 << bits) - 1;
    match cmb {
        ComboType::Concatenation => {
            let (h1, v1) = base_compress(iv1, m, bits);
            let (h2, v2) = base_compress(iv2, m, bits);
            (((h1 as u128) << 64) | (h2 as u128), v1, v2)
        }
        ComboType::XorSum => {
            let (h1, v1) = base_compress(iv1, m, bits);
            let (h2, v2) = base_compress(iv2, m, bits);
            ((h1 ^ h2) as u128, v1, v2)
        }
        ComboType::HashThenHash => {
            let (_, v1) = base_compress(iv1, m, bits);
            let (h2, v2) = base_compress(&v1, m, bits);
            ((h2 as u128) << 64, v1, v2)
        }
        ComboType::Interacting => {
            let (h1, v1) = base_compress(iv1, m, bits);
            let (h2, v2) = base_compress(&v1, m, bits); // h2 зависит от состояния первой функции
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
        ComboType::WidePipe => {
            // Имитация WidePipe: используем удвоенное внутреннее состояние
            let (h_w, v_w) = base_compress(iv1, m, bits * 2);
            let fh = h_w & mask;
            (((fh as u128) << 64) | (fh as u128), v_w.clone(), v_w)
        }
        ComboType::RobustInteraction => {
            let (h1, v1) = base_compress(iv1, m, bits);
            let (h2, v2) = base_compress(iv2, m ^ h1, bits); // Вторая функция зависит от выхода первой
            (((h1 & mask) as u128) << 64 | ((h2 & mask) as u128), v1, v2)
        }
    }
}

// --- ATTACKS ---

fn attack_direct(cmb: ComboType, bits: u32, params: &AttackParams) -> u64 {
    let mut seen = HashMap::with_capacity(params.direct_memory_cap.min(1_000_000));
    let (iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);

    for m in 0..params.direct_limit {
        let (h, _, _) = combine_step(cmb, &iv1, &iv2, m, bits);
        if seen.contains_key(&h) { return m; }
        if m < params.direct_memory_cap as u64 { seen.insert(h, m); }
    }
    params.direct_limit
}

fn attack_joux(cmb: ComboType, bits: u32, params: &AttackParams) -> u64 {
    let (mut iv1, iv2) = (vec![0xAA; 32], vec![0xBB; 32]);
    let mut msgs = vec![vec![]];
    let mut total_iters = 0;

    for _ in 0..params.joux_levels {
        let mut seen = HashMap::new();
        let mut m = 0;
        let (m1, m2, next_iv) = loop {
            total_iters += 1;
            let (h, v1, _) = combine_step(cmb, &iv1, &iv2, m, bits);
            let h1 = (h >> 64) as u64; // Хэш первой "трубы"
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
            let (_, _, v2) = combine_step(cmb, &iv1, &curr_iv2, m, bits);
            curr_iv2 = v2;
        }
        if seen_h2.contains_key(&curr_iv2) { return total_iters; }
        seen_h2.insert(curr_iv2, ());
    }
    total_iters
}

// --- MAIN ---

fn main() -> std::io::Result<()> {
    let mut log_file = OpenOptions::new().create(true).append(true).open("davies_meyer_combos.log")?;
    let bit_range = (26..=28).step_by(2);

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
        println!("\n--- Исследование: bits={} (Итоговый хэш до {} бит) ---", bits, bits * 2);
        println!("{:<20} | {:>12} | {:>12} | {:>8}", "Combination", "Dir Iter", "Joux Iter", "Ratio");
        println!("{}", "-".repeat(60));

        for cmb in &combos {
            let d = attack_direct(*cmb, bits, &params);
            let j = attack_joux(*cmb, bits, &params);
            let ratio = if j > 0 { d as f64 / j as f64 } else { 0.0 };

            let line = format!("{:<20?} | {:>12} | {:>12} | {:>8.2}x", cmb, d, j, ratio);
            println!("{}", line);
            writeln!(log_file, "{}", line)?;
        }
    }
    Ok(())
}