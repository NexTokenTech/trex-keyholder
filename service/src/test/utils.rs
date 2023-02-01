use std::time::SystemTime;
/// One minute in milliseconds.
const ONE_MINUTE: u64 = 60 * 1000;

/// Release time: take the current time and push it back 60s
pub fn test_release_time() -> u64 {
    let now = SystemTime::now();
    let mut now_time: u64 = 0;
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => {
            // it prints '2'
            println!("{}", elapsed.as_secs());
            now_time = elapsed.as_secs();
        },
        Err(e) => {
            // an error occurred!
            println!("Error: {:?}", e);
        },
    };
    // convert to milliseconds!
    now_time * 1000 + ONE_MINUTE
}