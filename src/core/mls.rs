//! MLS group management via the openmls crate.

// MLS group management via the OpenMLS library.
//
// Implements group creation, proposals, commits, message processing, and
// application data encryption/decryption via the openmls crate and
// the RustCrypto/basic_credential providers.
use openmls::prelude::*;
use tls_codec::Deserialize;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::key_packages::KeyPackageBundle;
use openmls::prelude::{Ciphersuite, GroupId, MlsMessageIn, ProcessedMessageContent};

/// A client‑side handle for MLS group operations.
/// A client-side handle for managing an MLS group via OpenMLS.
pub struct MlsClient {
    provider: OpenMlsRustCrypto,
    group: MlsGroup,
    signature_keys: SignatureKeyPair,
    credential_bundle: CredentialWithKey,
}

impl MlsClient {
    /// Create a new MLS client instance.
    ///
    /// `identity` is the user identity for the BasicCredential.
    /// `ciphersuite` is the MLS ciphersuite to use for group operations.
    /// `group_id` optionally sets an external GroupId.
    pub fn new(
        identity: Vec<u8>,
        ciphersuite: Ciphersuite,
        group_id: Option<GroupId>,
    ) -> Self {
        // Initialize the cryptographic provider.
        let provider = OpenMlsRustCrypto::default();

        // Generate signature key pair for the credential.
        let signature_keys =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("invalid signer");

        // Create the BasicCredential and CredentialWithKey.
        let credential = BasicCredential::new(identity);
        let credential_bundle = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        // Configure group creation.
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        // Build the underlying MLS group.
        let group = if let Some(gid) = group_id {
            MlsGroup::new_with_group_id(
                &provider,
                &signature_keys,
                &mls_group_create_config,
                gid,
                credential_bundle.clone(),
            )
            .expect("failed to create MLS group with GroupId")
        } else {
            MlsGroup::new(
                &provider,
                &signature_keys,
                &mls_group_create_config,
                credential_bundle.clone(),
            )
            .expect("failed to create MLS group")
        };

        Self {
            provider,
            group,
            signature_keys,
            credential_bundle,
        }
    }

    /// Propose addition of a new member (AddProposal).
    ///
    /// Returns the serialized Proposal message bytes for the given KeyPackageBundle.
    pub fn propose_member(&mut self, key_package_bundle: &KeyPackageBundle) -> Vec<u8> {
        let (proposal, _welcome_opt) = self
            .group
            .propose_add_member(
                &self.provider,
                &self.signature_keys,
                key_package_bundle.key_package(),
            )
            .expect("propose_add_member failed");
        proposal.to_bytes().expect("proposal serialization failed")
    }

    /// Commit pending proposals (CommitMessage).
    ///
    /// Returns the serialized Commit message bytes.
    pub fn commit(&mut self) -> Vec<u8> {
        let (mls_message_out, _welcome_opt, _group_info) = self
            .group
            .commit_to_pending_proposals(&self.provider, &self.signature_keys)
            .expect("commit_to_pending_proposals failed");
        mls_message_out
            .to_bytes()
            .expect("commit serialization failed")
    }

    /// Process an incoming MLS message (Proposal, Commit, or Welcome).
    pub fn process_message(&mut self, message: &[u8]) {
        // Deserialize the incoming MLS message and convert to ProtocolMessage
        let mut buf = message;
        let mls_in = MlsMessageIn::tls_deserialize(&mut buf)
            .expect("invalid MLS message bytes");
        let protocol_msg = mls_in
            .try_into_protocol_message()
            .expect("try_into_protocol_message failed");
        // Process the message (Proposal, Commit, or Welcome)
        let processed = self
            .group
            .process_message(&self.provider, protocol_msg)
            .expect("process_message failed");
        // If there is a staged commit, merge it
        if let ProcessedMessageContent::StagedCommitMessage(staged_box) = processed.into_content() {
            self.group
                .merge_staged_commit(&self.provider, *staged_box)
                .expect("merge_staged_commit failed");
        }
    }

    /// Encrypt application data for the group.
    ///
    /// Returns the serialized MLS ciphertext bytes.
    pub fn encrypt_app_data(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mls_out = self
            .group
            .create_message(&self.provider, &self.signature_keys, plaintext)
            .expect("create_message failed");
        mls_out
            .to_bytes()
            .expect("message serialization failed")
    }

    /// Decrypt application data for the group.
    ///
    /// Returns the plaintext bytes.
    pub fn decrypt_app_data(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        // Deserialize and process the application MLS message to recover plaintext
        let mut buf = ciphertext;
        let mls_in = MlsMessageIn::tls_deserialize(&mut buf)
            .expect("invalid MLS message bytes");
        // Convert to ProtocolMessage and process to obtain plaintext
        let protocol_msg = mls_in
            .try_into_protocol_message()
            .expect("try_into_protocol_message failed");
        let processed = self
            .group
            .process_message(&self.provider, protocol_msg)
            .expect("process_message failed");
        if let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content() {
            application.into_bytes()
        } else {
            panic!("expected application message content");
        }
    }
}
