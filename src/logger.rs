#[macro_export]
macro_rules! log_info {
    ($($args: tt)*) => {
        println!("\u{001b}[36m[INFO] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($args: tt)*) => {
        println!("\u{001b}[35m[DBUG] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($args: tt)*) => {
        println!("\u{001b}[33m[WARN] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($args: tt)*) => {
        println!("\u{001b}[31m[ERRO] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
    };
}

#[macro_export]
macro_rules! ignore_result_and_log_error {
    ($($args: tt)*) => {
        match $($args)* {
            Ok(_) => {},
            Err(error) => println!("\u{001b}[31m[ERRO] {}: {:?}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), error),
        }
    };
}