use rand::{thread_rng, Rng};

const SYMBOLS: [char; 62] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
                             'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                             's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
                             'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                             'U', 'V', 'W', 'X', 'Y', 'Z'];
const BASE: u64 = 62;

pub fn random_token() -> String {
    encode(10000000 + thread_rng().gen_range::<u64>(0, 1000000000))
}

// FIXME this can be made MUCH faster
pub fn encode(number: u64) -> String {
    let rest = number % BASE;

    let mut encoded_str = String::new();
    encoded_str.push(SYMBOLS[rest as usize]);

    if (number - rest) != 0 {
        let newnumber = (number - rest) / BASE;
        encoded_str = encode(newnumber) + &encoded_str;
    }

    encoded_str
}

// decodes a string
#[allow(dead_code)]
pub fn decode(input: &str) -> u64 {
    let floatbase = BASE as f64;
    let input_length = input.len() as i32;

    let mut sum = 0;
    for (index, current_char) in input.char_indices().rev() {
        let pos_char = find_char_in_symbols(current_char).unwrap() as u64;
        sum = sum + (pos_char * floatbase.powi(input_length - index as i32 - 1) as u64);
    }

    sum
}

#[allow(dead_code)]
fn find_char_in_symbols(c: char) -> Option<usize> {
    for index in 0..BASE {
        if SYMBOLS[index as usize] == c {
            return Option::Some(index as usize);
        }
    }
    Option::None
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(1000000), String::from("4c92"));
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("4c92"), 1000000);
    }

    #[test]
    fn test_encode_decode1() {
        let number: u64 = 1234567890;
        let encoded_val = encode(number);
        assert_eq!(decode(&encoded_val), number);
    }

    #[test]
    fn test_encode_decode2() {
        let number: u64 = 9876543210;
        let encoded_val = encode(number);
        assert_eq!(decode(&encoded_val), number);
    }

    #[test]
    fn test_encode_decode3() {
        let number: u64 = 99889999998889;
        let encoded_val = encode(number);
        assert_eq!(decode(&encoded_val), number);
    }
}