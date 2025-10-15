use std::ops::Range;

use crate::MESSAGE_LENGTH;
use rand::Rng;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Error enum for the signing process.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Occurs when the probabilistic message encoding fails to produce a valid codeword
    /// after the maximum number of attempts.
    #[error("Failed to encode message after {attempts} attempts.")]
    EncodingAttemptsExceeded { attempts: usize },
}

/// Defines the interface for a synchronized signature scheme secret key.
///
/// The secret key can be used for epochs in a certain interval, called the activation
/// interval. At any point in time, it is prepared for signing for epochs in a certain
/// sub-interval of the activation interval (this could be the full activation interval).
/// There is a function that changes this prepared interval to the next one, if possible.
pub trait SignatureSchemeSecretKey {
    /// Returns the interval during which this key is currently active.
    /// This is guaranteed to be a superset of the activation interval that has been
    /// passed during key generation. It starts at a multiple of sqrt{LIFETIME} and
    /// its length is also a multiple of sqrt{LIFETIME}. Its length is at least
    /// 2 * sqrt{LIFETIME}. The activation interval does not change.
    fn get_activation_interval(&self) -> Range<u64>;

    /// Returns the interval for which this key has been prepared (for signing future messages).
    /// It's a sub-interval of the activation interval. It starts at a multiple of sqrt{LIFETIME}.
    /// It has length exactly 2 * sqrt{LIFETIME}.
    fn get_prepared_interval(&self) -> Range<u64>;

    /// Advances the prepared interval to the next one with overlap of time sqrt{LIFETIME}, if possible.
    /// Example: prepared_interval is [a, a + 2 * sqrt{LIFETIME}) before calling this. Then it it will
    /// be [a + sqrt{LIFETIME}, a + 3 * sqrt{LIFETIME}) after calling this, provided that this new
    /// interval is also a sub-interval of the activation interval. If not, then the prepared interval
    /// does not change.
    ///
    /// Note: the caller should only call this if signing for the epochs in [a, a + sqrt{LIFETIME}) is
    /// no longer needed.
    fn advance_preparation(&mut self);
}

/// Defines the interface for a **synchronized signature scheme**.
///
/// ## Overview
///
/// In a synchronized (or stateful) signature scheme, keys are associated with a fixed
/// lifetime, which is divided into discrete time periods called **epochs**. A key pair
/// is restricted to signing only once per epoch. Reusing an epoch to sign a
/// different message or even the same message again will compromise the security of the scheme.
///
/// This model is particularly well-suited for consensus protocols like Ethereum's
/// proof-of-stake (lean Ethereum), where validators sign messages
/// (e.g., block proposals or attestations) at regular, predetermined intervals.
///
/// ## Theoretical Foundation
///
/// This trait abstracts the family of post-quantum signature schemes presented in
/// "Hash-Based Multi-Signatures for Post-Quantum Ethereum" [DKKW25a] and its
/// extension "LeanSig for Post-Quantum Ethereum" [DKKW25b]. These schemes are variants of
/// the **eXtended Merkle Signature Scheme (XMSS)**, which builds a many-time signature
/// scheme from a one-time signature (OTS) primitive and a Merkle tree.
///
/// References:
/// [DKKW25a] https://eprint.iacr.org/2025/055.pdf
/// [DKKW25b] https://eprint.iacr.org/2025/1332.pdf
pub trait SignatureScheme {
    /// The public key used for verification.
    ///
    /// The key must be serializable to allow for network transmission and storage.
    type PublicKey: Serialize + DeserializeOwned;

    /// The secret key used for signing.
    ///
    /// The key must be serializable for persistence and secure backup.
    type SecretKey: SignatureSchemeSecretKey + Serialize + DeserializeOwned;

    /// The signature object produced by the signing algorithm.
    ///
    /// The signature must be serializable to allow for network transmission and storage.
    type Signature: Serialize + DeserializeOwned;

    /// The maximum number of epochs supported by this signature scheme configuration,
    /// denoted as $L$ in the literature [DKKW25a, DKKW25b].
    ///
    /// This constant defines the total number of epochs available, i.e., valid epochs range
    /// from `0` to `LIFETIME - 1`. While this is the maximum possible lifetime, an individual
    /// key pair can be generated to be active for a shorter, specific range of epochs within
    // this total lifetime using the`key_gen` function.
    ///
    /// This value **must** be a power of two.
    const LIFETIME: u64;

    /// Generates a new cryptographic key pair.
    ///
    /// This function creates a fresh public key for verifying signatures and a
    /// corresponding secret key for creating them.
    ///
    /// ### Active Range
    ///
    /// The generated key pair is configured to be active only for a specific sub-range
    /// of its total `LIFETIME`. This is a practical optimization for key management,
    /// allowing a single cryptographic setup to support keys with different lifespans.
    ///
    /// The active period covers all epochs in the range
    /// `activation_epoch..activation_epoch + num_active_epochs`.
    ///
    /// ### Parameters
    /// * `rng`: A cryptographically secure random number generator.
    /// * `activation_epoch`: The starting epoch for which this key is active.
    /// * `num_active_epochs`: The number of consecutive epochs for which this key is active.
    ///
    /// ### Returns
    /// A tuple containing the new `(PublicKey, SecretKey)`.
    fn key_gen<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Produces a digital signature for a given message at a specific epoch.
    ///
    /// This method cryptographically binds a message to the signer's identity for a
    /// single, unique epoch. Callers must ensure they never call this function twice
    /// with the same secret key and for the same epoch, as this would compromise security.
    /// The signing process is deterministic.
    ///
    /// Note: we derandomize the signing function as an additional hardening mechanism.
    /// This ensures that if the caller calls the function twice with the same input
    /// triple (i.e., same key, epoch, message), the result is the same. In particular,
    /// this does not compromise security. We still recommend that the caller only calls
    /// this function once for the same key-epoch pair, to avoid accidentally calling it
    /// twice with two different messages, which would compromise security.
    ///
    /// Note: It is well-known that the security guarantees of signature schemes are not
    /// weakened if we derandomize signing using a PRF.
    ///
    /// ### Parameters
    /// * `sk`: A reference to the secret key to be used for signing.
    /// * `epoch`: The specific epoch for which the signature is being created.
    /// * `message`: A fixed-size byte array representing the message to be signed.
    ///
    /// ### Returns
    /// A `Result` which is:
    /// * `Ok(Self::Signature)` on success, containing the generated signature.
    /// * `Err(SigningError)` on failure.
    fn sign(
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError>;

    /// Verifies a digital signature against a public key, message, and epoch.
    ///
    /// This function determines if a signature is valid and was generated by the
    /// holder of the corresponding secret key for the specified message and epoch.
    ///
    /// ### Parameters
    /// * `pk`: A reference to the public key against which to verify the signature.
    /// * `epoch`: The epoch the signature corresponds to.
    /// * `message`: The message that was supposedly signed.
    /// * `sig`: A reference to the signature to be verified.
    ///
    /// ### Returns
    /// `true` if the signature is valid according to the scheme's rules, `false` otherwise.
    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool;

    /// A test-only function to assert that all internal parameters chosen for the
    /// signature scheme are valid and compatible.
    ///
    /// ### Panics
    /// This function will panic if any of the internal consistency checks fail.
    #[cfg(test)]
    fn internal_consistency_check();
}

pub mod generalized_xmss;

#[cfg(test)]
mod test_templates {
    use serde::{Serialize, de::DeserializeOwned};

    use super::*;

    /// Generic test for any implementation of the `SignatureScheme` trait.
    /// Tests correctness, i.e., that honest key gen, honest signing, implies
    /// that the verifier accepts the signature. A random message is used.
    pub fn test_signature_scheme_correctness<T: SignatureScheme>(
        epoch: u32,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) {
        // The epoch must be in the activation interval
        assert!(
            activation_epoch as u32 <= epoch
                && epoch < (activation_epoch + num_active_epochs) as u32,
            "Did not even try signing, epoch {:?} outside of activation interval {:?},{:?}",
            epoch,
            activation_epoch,
            num_active_epochs
        );

        let mut rng = rand::rng();

        // Generate a key pair
        let (pk, mut sk) = T::key_gen(&mut rng, activation_epoch, num_active_epochs);

        // Advance the secret key until the epoch is in the prepared interval
        let mut iterations = 0;
        while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
            sk.advance_preparation();
            iterations += 1;
        }
        assert!(
            sk.get_prepared_interval().contains(&(epoch as u64)),
            "Did not even try signing, failed to advance key preparation to desired epoch {:?}.",
            epoch
        );

        // Sample random test message
        let message = rng.random();

        // Sign the message
        let signature = T::sign(&sk, epoch, &message);

        // Ensure signing was successful
        assert!(
            signature.is_ok(),
            "Signing failed: {:?}. Epoch was {:?}",
            signature.err(),
            epoch
        );

        // Verify the signature
        let signature = signature.unwrap();
        let is_valid = T::verify(&pk, epoch, &message, &signature);
        assert!(
            is_valid,
            "Signature verification failed. . Epoch was {:?}",
            epoch
        );

        test_bincode_round_trip_consistency(&pk);
        test_bincode_round_trip_consistency(&sk);
        test_bincode_round_trip_consistency(&signature);
    }

    fn test_bincode_round_trip_consistency<T: Serialize + DeserializeOwned>(ori: &T) {
        use bincode::serde::{decode_from_slice, encode_to_vec};
        let config = bincode::config::standard();
        let bytes_ori = encode_to_vec(ori, config).expect("Bincode encode should not fail");
        let (dec, _): (T, _) =
            decode_from_slice(&bytes_ori, config).expect("Bincode decode should not fail");
        let bytes_dec = encode_to_vec(dec, config).expect("Bincode encode should not fail");
        assert_eq!(bytes_ori, bytes_dec, "Serde consistency check failed");
    }
}
