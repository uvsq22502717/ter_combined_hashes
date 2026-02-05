use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::{Instant, Duration};

/// Helper: H(iv || input) truncated to target_bits
fn h(iv: &[u8], input: u32, mask: u32) -> (u32, Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(iv);
    hasher.update(input.to_le_bytes());
    let result = hasher.finalize();
    let truncated = u32::from_be_bytes(result[0..4].try_into().unwrap()) & mask;
    (truncated, result.to_vec())
}

/// HashMap-based collision search (follows the functional sequence)
fn find_collision_hashmap(iv: &[u8], mask: u32) -> (u32, u32, Vec<u8>, Duration) {
    let start_time = Instant::now();
    let mut seen = HashMap::new();
    let mut current = 0u32; // Starting point

    loop {
        let (next_h, full_hash) = h(iv, current, mask);
        if let Some((old_val, _)) = seen.insert(next_h, (current, full_hash.clone())) {
            return (old_val, current, full_hash, start_time.elapsed());
        }
        current = next_h; // Follow the sequence x_{n+1} = H(x_n)
    }
}

/// Floyd's Cycle-Finding Algorithm
fn find_collision_floyd(iv: &[u8], mask: u32) -> (u32, u32, Vec<u8>, Duration) {
    let start_time = Instant::now();
    let mut tortoise = 0u32;
    let mut hare = 0u32;

    loop {
        tortoise = h(iv, tortoise, mask).0;
        hare = h(iv, h(iv, hare, mask).0, mask).0;
        if tortoise == hare { break; }
    }

    tortoise = 0;
    let mut prev_t = tortoise;
    let mut prev_h = hare;
    while tortoise != hare {
        prev_t = tortoise;
        prev_h = hare;
        tortoise = h(iv, tortoise, mask).0;
        hare = h(iv, hare, mask).0;
    }

    let (_, full_hash) = h(iv, tortoise, mask);
    (prev_t, prev_h, full_hash, start_time.elapsed())
}

fn main() {
    let target_bits = 20;
    let num_steps = 100;
    let mask = (1 << target_bits) - 1;
    let initial_iv = vec![0u8; 32];

    println!("--- MULTICOLLISION BENCHMARK: HASHMAP VS FLOYD ---");
    println!("Target bits: {} | Steps: {}\n", target_bits, num_steps);

    let mut iv_map = initial_iv.clone();
    let mut iv_floyd = initial_iv.clone();
    
    println!("{:<5} | {:<20} | {:<20} | {:<10}", "Step", "HashMap (m1, m2)", "Floyd (m1, m2)", "Status");
    println!("{}", "-".repeat(65));

    let mut total_time_map = Duration::ZERO;
    let mut total_time_floyd = Duration::ZERO;

    for i in 1..=num_steps {
        let (m1_m, m2_m, next_iv_m, dur_m) = find_collision_hashmap(&iv_map, mask);
        let (m1_f, m2_f, next_iv_f, dur_f) = find_collision_floyd(&iv_floyd, mask);

        let status = if m1_m == m1_f && m2_m == m2_f { "MATCH" } else { "DIFF" };

        println!("{:<5} | ({:<8}, {:<8}) | ({:<8}, {:<8}) | {:<10}", 
                 i, m1_m, m2_m, m1_f, m2_f, status);

        iv_map = next_iv_m;
        iv_floyd = next_iv_f;
        total_time_map += dur_m;
        total_time_floyd += dur_f;
    }

    println!("{}", "-".repeat(65));
    println!("Total Time HashMap: {:?}", total_time_map);
    println!("Total Time Floyd:   {:?}", total_time_floyd);
    
    let ratio = total_time_floyd.as_secs_f64() / total_time_map.as_secs_f64();
    println!("\nFloyd is {:.2}x slower than HashMap, but uses O(1) memory.", ratio);
}