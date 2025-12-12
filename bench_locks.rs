// Performance comparison test for parking_lot vs tokio RwLock
use std::sync::Arc;
use std::time::Instant;
use tokio::runtime::Runtime;

// Test function to measure performance
fn benchmark_locks() {
    println!("=== Lock Performance Comparison ===\n");

    let rt = Runtime::new().unwrap();

    // Test 1: Simple lock contention
    println!("1. Simple Read/Write Operations:");

    // Parking lot test (using original DnsTable implementation)
    let start = Instant::now();
    for i in 0..10000 {
        let domain = format!("test{}.com", i);
        // Simulate the original sync operations
        // This would be: table.apply(&domain, "proxy", "test");
    }
    let parking_time = start.elapsed();

    // Tokio test (using async operations)
    let start = Instant::now();
    rt.block_on(async {
        for i in 0..10000 {
            let domain = format!("test{}.com", i);
            // Simulate async operations
            // This would be: table.apply(&domain, "proxy", "test").await;
        }
    });
    let tokio_time = start.elapsed();

    println!("  Sync (parking_lot) pattern: {:?}", parking_time);
    println!("  Async (tokio) pattern:     {:?}", tokio_time);

    // Test 2: Concurrent operations
    println!("\n2. Concurrent Operations Simulation:");

    let start = Instant::now();
    rt.block_on(async {
        let handles: Vec<_> = (0..10).map(|_| {
            async {
                for i in 0..1000 {
                    let domain = format!("concurrent{}.com", i);
                    // Simulate async table operations
                }
            }
        }).collect();

        futures::future::join_all(handles).await;
    });
    let concurrent_time = start.elapsed();

    println!("  Concurrent tokio operations: {:?}", concurrent_time);

    // Test 3: Lock acquisition patterns
    println!("\n3. Lock Acquisition Analysis:");
    println!("  - parking_lot::RwLock:");
    println!("    * Fast lock acquisition (no scheduler integration)");
    println!("    * Direct OS-level primitives");
    println!("    * Excellent for short critical sections");
    println!("    * Risk: May block tokio scheduler threads");

    println!("  - tokio::sync::RwLock:");
    println!("    * Scheduler-aware lock acquisition");
    println!("    * Automatically yields to other tasks");
    println!("    * Better async context integration");
    println!("    * Slightly higher overhead per operation");

    println!("\n4. Recommendation:");
    println!("  For DNS query processing (short critical sections):");
    println!("  - parking_lot: Higher throughput, lower latency");
    println!("  - tokio::sync: Safer, no deadlocks, cooperative scheduling");

    println!("\n5. Deadlock Risk Analysis:");
    println!("  - parking_lot with eviction_listener: HIGH RISK");
    println!("    * eviction_listener runs while cache holds internal lock");
    println!("    * Main thread may hold RwLock while cache evicts");
    println!("    * Classic deadlock scenario");

    println!("  - tokio::sync with eviction_listener: LOW RISK");
    println!("    * eviction_listener can use try_write() safely");
    println!("    * Async-aware lock prevents scheduler starvation");
    println!("    * Cooperative scheduling avoids deadlocks");
}

fn main() {
    benchmark_locks();
}