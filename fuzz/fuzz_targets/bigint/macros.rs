#[macro_export]
macro_rules! match_bigint_type {
    ($bigint_enum:expr, $method:ident $(, $args:expr)* ) => {
        match $bigint_enum {
            BigIntType::U64(_)  => U64::$method($($args),*),
            BigIntType::U254(_) => U254::$method($($args),*),
            BigIntType::U256(_) => U256::$method($($args),*),
            BigIntType::U384(_) => U384::$method($($args),*),
        }
    };
} 