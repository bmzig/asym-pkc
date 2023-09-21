mod montgomery;
mod utils;
mod constants;
mod edwards;
mod window;
mod projective;
mod projective_test;

#[cfg(test)]
mod crate_tests {

    use crate::window::LookupTable;

    #[test]
    fn ed25519_explicit() {
    }

    #[test]
    fn ed25519_random() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(move || {
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap(); });
    }

    #[test]
    fn ed25519_should_fail() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(move || {
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap(); });
    }

    #[test]
    fn ed25519_constant_time() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(move || {
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap(); });
    }

    // #[test]
    #[allow(non_snake_case, dead_code)]
    fn ed25519_wNAF() {
        let _lt = LookupTable::initialize_window8();
        for _ in 0..10 {
        }
    }

}
