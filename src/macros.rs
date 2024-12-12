#[macro_export]
macro_rules! log_info {
    ($($args: tt)*) => {
        if cfg!(feature = "log_info") {
            println!("\u{001b}[36m[INFO] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($args: tt)*) => {
        if cfg!(feature = "log_debug") {
            println!("\u{001b}[35m[DBUG] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($args: tt)*) => {
        if cfg!(feature = "log_warn") {
            println!("\u{001b}[33m[WARN] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*)) 
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($args: tt)*) => {
        if cfg!(feature = "log_error") {
            println!("\u{001b}[31m[ERRO] {}: {}\u{001b}[0m", Into::<chrono::DateTime<chrono::offset::Local>>::into(std::time::SystemTime::now()).format("%Y/%m/%d %T"), format!($($args)*))
        }
    };
}

#[macro_export]
macro_rules! ignore_result_and_log_error {
    ($x:expr) => {
        match $x {
            Ok(_) => {},
            Err(error) => log_error!("{}", error),
        }
    };
}

#[macro_export]
macro_rules! return_result_or_log_error_continue {
    ($x:expr, $message:expr) => {
        match $x {
            Ok(a) => a,
            Err(error) => {
                log_error!("{}: {}", $message, error);
                continue;
            }
        }
    };
}

#[macro_export]
macro_rules! ignore_result_or_log_error_continue {
    ($x:expr, $message:expr) => {
        match $x {
            Ok(_) => {},
            Err(error) => {
                log_error!("{}: {}", $message, error);
                continue;
            }
        }
    };
}
