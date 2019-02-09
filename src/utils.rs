#[macro_export]
macro_rules! enum_variant {
    ($val:expr, $variant:path) => {
        match $val {
            $variant(x) => x,
            _ => panic!(
                "Got wrong enum variant. Was expecting {}",
                stringify!($variant)
            ),
        }
    };
}
