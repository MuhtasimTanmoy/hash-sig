use zkhash::ark_ff::One;
use zkhash::ark_ff::UniformRand;
use zkhash::ark_ff::Zero;
use zkhash::poseidon2::poseidon2_instance_babybear::POSEIDON2_BABYBEAR_24_PARAMS;
use zkhash::{fields::babybear::FpBabyBear, poseidon2::poseidon2::Poseidon2};

use super::TweakableHash;

// TODO: Check if we want to use this field or a different one
type F = FpBabyBear;

/// Enum to implement tweaks.
pub enum PoseidonTweak<
    const LOG_LIFETIME: usize,
    const CEIL_LOG_NUM_CHAINS: usize,
    const CHUNK_SIZE: usize,
> {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u32,
        pos_in_chain: u32,
    },
    _Marker(std::marker::PhantomData<F>),
}

impl<const LOG_LIFETIME: usize, const CEIL_LOG_NUM_CHAINS: usize, const CHUNK_SIZE: usize>
    PoseidonTweak<LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE>
{
    const TWEAK_LEN: usize = 6;

    fn to_field_elements(&self) -> Vec<F> {
        // TODO: implement tweaks properly
        // we need to convert from integers to field elements,
        // Note: taking into account the constants
        // LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE,
        // we know that the tweak can be represented using at most
        // LOG_LIFETIME + CEIL_LOG_NUM_CHAINS + CHUNK_SIZE many
        // bits.
        vec![F::zero(); Self::TWEAK_LEN]
    }
}

/// Function to first pad input to appropriate length and
/// then apply the Poseidon permutation.
fn poseidon_padded_permute(instance: &Poseidon2<F>, input: &[F]) -> Vec<F> {
    assert!(
        input.len() <= instance.get_t(),
        "Poseidon Compression: Input length too large for Poseidon parameters."
    );

    // pad input with zeroes to have exactly length instance.get_t()
    let mut padded_input = input.to_vec();
    padded_input.resize_with(instance.get_t(), F::zero);

    // apply permutation and return
    instance.permutation(&padded_input)
}

/// Poseidon Compression Function, using the Poseidon Permutation.
/// It works as PoseidonCompress(x) = Truncate(PoseidonPermute(x) + x)
pub fn poseidon_compress<const OUT_LEN: usize>(
    instance: &Poseidon2<F>,
    input: &[F],
) -> [F; OUT_LEN] {
    assert!(
        input.len() >= OUT_LEN,
        "Poseidon Compression: Input length must be at least output length."
    );

    // first permute input
    let permuted_input = poseidon_padded_permute(instance, input);
    // now, add them, but only for the positions
    // we actually output.
    let mut output = [F::one(); OUT_LEN];
    for i in 0..OUT_LEN {
        output[i] = permuted_input[i] + input[i];
    }
    output
}

/// A tweakable hash function implemented using Poseidon2
///
/// Note: HASH_LEN and PARAMETER_LEN must be given in
/// the unit "number of field elements".
pub struct PoseidonTweakHash<
    const LOG_LIFETIME: usize,
    const CEIL_LOG_NUM_CHAINS: usize,
    const CHUNK_SIZE: usize,
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
>;

impl<
        const LOG_LIFETIME: usize,
        const CEIL_LOG_NUM_CHAINS: usize,
        const CHUNK_SIZE: usize,
        const PARAMETER_LEN: usize,
        const HASH_LEN: usize,
    > TweakableHash
    for PoseidonTweakHash<LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE, PARAMETER_LEN, HASH_LEN>
{
    type Parameter = [F; PARAMETER_LEN];

    type Tweak = PoseidonTweak<LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE>;

    type Domain = [F; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        let mut par = [F::one(); PARAMETER_LEN];
        for i in 0..PARAMETER_LEN {
            par[i] = F::rand(rng);
        }
        par
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        let mut dom = [F::one(); HASH_LEN];
        for i in 0..HASH_LEN {
            dom[i] = F::rand(rng);
        }
        dom
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u32, pos_in_chain: u32) -> Self::Tweak {
        PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        }
    }

    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain {
        assert!(
            PARAMETER_LEN + Self::Tweak::TWEAK_LEN + 2 * HASH_LEN <= 24,
            "Poseidon Tweak Hash: Input lengths too large for Poseidon instance"
        );

        // we are in one of three cases:
        // (1) hashing within chains. We use compression mode.
        // (2) hashing two siblings in the tree. We use compression mode.
        // (3) hashing a long vector of chain ends. We use sponge mode.

        let l = message.len();
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);
        if l == 1 {
            // we compress parameter, tweak, message
            let message_unpacked = message[0];
            let tweak_fe = tweak.to_field_elements();
            let combined_input: Vec<F> = parameter
                .iter()
                .chain(tweak_fe.iter())
                .chain(message_unpacked.iter())
                .cloned()
                .collect();
            return poseidon_compress::<HASH_LEN>(&instance, &combined_input);
        }
        if l == 2 {
            // we compress parameter, tweak, message (now containing two parts)
            let message_unpacked_left = message[0];
            let message_unpacked_right = message[1];
            let tweak_fe = tweak.to_field_elements();
            let combined_input: Vec<F> = parameter
                .iter()
                .chain(tweak_fe.iter())
                .chain(message_unpacked_left.iter())
                .chain(message_unpacked_right.iter())
                .cloned()
                .collect();
            return poseidon_compress::<HASH_LEN>(&instance, &combined_input);
        }
        if l > 2 {
            // TODO: implement Sponge mode
            return [F::one(); HASH_LEN];
        }
        // will never be reached
        [F::one(); HASH_LEN]
    }
}

// Example instantiations
pub type PoseidonTweak44 = PoseidonTweakHash<20, 8, 2, 4, 4>;
pub type PoseidonTweak37 = PoseidonTweakHash<20, 8, 2, 3, 7>;

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_apply_44() {
        let mut rng = thread_rng();

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let message_two = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        PoseidonTweak44::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak44::chain_tweak(2, 3, 4);
        PoseidonTweak44::apply(&parameter, &tweak_chain, &[message_one]);
    }

    #[test]
    fn test_apply_37() {
        let mut rng = thread_rng();

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let message_two = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak37::tree_tweak(0, 3);
        PoseidonTweak37::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak37::chain_tweak(2, 3, 4);
        PoseidonTweak37::apply(&parameter, &tweak_chain, &[message_one]);
    }
}
