use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::{Instant, Duration};

/// H1 and H2 are simulated using different Initial Vectors (IV)
const IV1: [u8; 32] = [0x00; 32];
const IV2: [u8; 32] = [0xFF; 32];

/// Compression function h: mimics a Merkle-Damgard iteration
fn h(iv: &[u8], input: u64, target_bits: u32) -> (u64, Vec<u8>) {
    let mut hasher = Sha256::new();
    // In Merkle-Damgard, the state (IV) is updated with the message block
    hasher.update(iv);
    hasher.update(input.to_le_bytes());
    let result = hasher.finalize();
    
    let truncated = u64::from_be_bytes(result[0..8].try_into().unwrap());
    // Create a bitmask for the truncated hash comparison
    let mask = if target_bits >= 64 { !0u64 } else { (1u64 << target_bits) - 1 };
    
    (truncated & mask, result.to_vec())
}

/// DIRECT ATTACK: Searches for a collision for H1(m) || H2(m) simultaneously.
/// This approach assumes the security of the concatenation is the sum of the bits.
fn find_concatenated_collision(target_bits: u32) -> Duration {
    let start = Instant::now();
    let mut seen = HashMap::new();
    let mut m = 0u64;

    loop {
        let h1 = h(&IV1, m, target_bits).0;
        let h2 = h(&IV2, m, target_bits).0;
        // Combine two hashes into a single 128-bit value (simulating concatenation)
        let combined = (h1 as u128) << 64 | (h2 as u128);

        if seen.contains_key(&combined) {
            return start.elapsed();
        }
        seen.insert(combined, m);
        m += 1;
        
        // Progress indicator for long-running direct attacks
        if m % 1000000 == 0 { 
            println!("  ...checked {} million combinations", m / 1000000); 
        }
    }
}

/// JOUX'S ATTACK: Leverages multicollisions in H1 to break the concatenated hash.
/// Complexity is O(n * 2^(n/2)) instead of O(2^n).
fn find_joux_collision(target_bits: u32) -> Duration {
    let start = Instant::now();
    let num_steps = target_bits; // We need n steps to generate 2^n multicollisions
    let mut current_iv_h1 = IV1.to_vec();
    
    // Each element in this Vec is a sequence of message blocks
    let mut multicollision_messages = vec![vec![]];

    println!("  Step 1: Building multicollision for H1 ({} rounds needed)", num_steps);
    for _ in 0..num_steps {
        let mut seen = HashMap::new();
        let mut m = 0u64;
        
        // Find a single collision for the current IV
        let (m1, m2, next_iv) = loop {
            let (res, full) = h(&current_iv_h1, m, target_bits);
            if let Some(old_m) = seen.insert(res, m) {
                break (old_m, m, full);
            }
            m += 1;
        };

        // Double the number of messages by appending either m1 or m2 to each existing chain
        let mut next_gen = Vec::new();
        for msg_list in multicollision_messages {
            let mut clone1 = msg_list.clone();
            clone1.push(m1);
            next_gen.push(clone1);

            let mut clone2 = msg_list;
            clone2.push(m2);
            next_gen.push(clone2);
        }
        multicollision_messages = next_gen;
        current_iv_h1 = next_iv; // Update IV for the next round (Merkle-Damgard chaining)
    }

    println!("  Step 2: Searching for a collision in H2 among {} generated messages", multicollision_messages.len());
    let mut seen_h2 = HashMap::new();
    
    for msg_list in multicollision_messages {
        // Calculate H2 for the entire chain of blocks
        let mut current_iv_h2 = IV2.to_vec();
        for &block in &msg_list {
            current_iv_h2 = h(&current_iv_h2, block, target_bits).1;
        }
        
        let h2_final = u64::from_be_bytes(current_iv_h2[0..8].try_into().unwrap());
        let mask = if target_bits >= 64 { !0u64 } else { (1u64 << target_bits) - 1 };
        let h2_truncated = h2_final & mask;

        if seen_h2.contains_key(&h2_truncated) {
            return start.elapsed();
        }
        seen_h2.insert(h2_truncated, msg_list);
    }
    start.elapsed()
}

fn main() {
    // Note: target_bits = 16 means the combined hash is 32 bits.
    // A direct attack on 32 bits is feasible, but 40+ bits will be very slow.
    let target_bits = 24; 
    
    println!("--- COMPARISON: DIRECT ATTACK VS JOUX'S ATTACK ---");
    println!("Target bits per function: {} | Combined Hash: {} bits\n", target_bits, target_bits * 2);

    println!("1. Starting Direct Attack (Birthday Attack on Concatenation)...");
    let time_concat = find_concatenated_collision(target_bits);
    println!("   Completed in: {:?}\n", time_concat);

    println!("2. Starting Antoine Joux's Attack (Multicollision Method)...");
    let time_joux = find_joux_collision(target_bits);
    println!("   Completed in: {:?}\n", time_joux);

    let speedup = time_concat.as_secs_f64() / time_joux.as_secs_f64();
    println!("RESULT: Joux's attack is {:.2}x faster than the direct approach!", speedup);
}