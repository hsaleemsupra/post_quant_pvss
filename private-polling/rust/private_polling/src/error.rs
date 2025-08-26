use thiserror::Error;
#[derive(Error, Debug)]
pub enum PrivatePollingError {
    #[error("General err:{0}")]
    GeneralError(String),
    #[error("Failed to fetch polls:{0}")]
    FetchPollsError(String),
    #[error("Message is not well formed")]
    MessageNotWellFormed,
    #[error("Missing polls")]
    MissingPolls,
    #[error("Missing partial decryption for poll {0}")]
    MissingPartialDecryptionForPoll(u64),
    #[error("Failed to verify partial decryption")]
    FailedToVerifyPartialDecryption,
    #[error("Failed to create partial decryption: {0}")]
    FailedToCreatePartialDecryption(String),
    #[error("Failed to encrypt data: {0}")]
    EncryptionFailed(String),
    #[error("Failed to decrypt final result: {0}")]
    DecryptionFailed(String),
    #[error("Failed to post poll result error:{0}")]
    PostPollResultError(String),
    #[error("Deserialization error:{0}")]
    DeserializationError(String)
}