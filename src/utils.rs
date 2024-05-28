use bitcoin_scriptexec::ExecError;
use zulu_bitcoin_scriptexec::ExecError as Test_ExecError;

pub fn test_exec_error_transform(error: Option<Test_ExecError>) -> Option<ExecError> {
    if let Some(err) = error.clone() {
        let error = match err {
            zulu_bitcoin_scriptexec::ExecError::DisabledOpcode => ExecError::DisabledOpcode,
            zulu_bitcoin_scriptexec::ExecError::OpCodeseparator => ExecError::OpCodeseparator,
            zulu_bitcoin_scriptexec::ExecError::BadOpcode => ExecError::BadOpcode,
            zulu_bitcoin_scriptexec::ExecError::OpCount => ExecError::OpCount,
            zulu_bitcoin_scriptexec::ExecError::PushSize => ExecError::PushSize,
            zulu_bitcoin_scriptexec::ExecError::MinimalData => ExecError::MinimalData,
            zulu_bitcoin_scriptexec::ExecError::InvalidStackOperation => {
                ExecError::InvalidStackOperation
            }
            zulu_bitcoin_scriptexec::ExecError::NegativeLocktime => ExecError::NegativeLocktime,
            zulu_bitcoin_scriptexec::ExecError::UnsatisfiedLocktime => {
                ExecError::UnsatisfiedLocktime
            }
            zulu_bitcoin_scriptexec::ExecError::UnbalancedConditional => {
                ExecError::UnbalancedConditional
            }
            zulu_bitcoin_scriptexec::ExecError::TapscriptMinimalIf => ExecError::TapscriptMinimalIf,
            zulu_bitcoin_scriptexec::ExecError::Verify => ExecError::Verify,
            zulu_bitcoin_scriptexec::ExecError::OpReturn => ExecError::OpReturn,
            zulu_bitcoin_scriptexec::ExecError::EqualVerify => ExecError::EqualVerify,
            zulu_bitcoin_scriptexec::ExecError::NumEqualVerify => ExecError::NumEqualVerify,
            zulu_bitcoin_scriptexec::ExecError::CheckSigVerify => ExecError::CheckSigVerify,
            zulu_bitcoin_scriptexec::ExecError::TapscriptValidationWeight => {
                ExecError::TapscriptValidationWeight
            }
            zulu_bitcoin_scriptexec::ExecError::PubkeyType => ExecError::PubkeyType,
            zulu_bitcoin_scriptexec::ExecError::SchnorrSigSize => ExecError::SchnorrSigSize,
            zulu_bitcoin_scriptexec::ExecError::SchnorrSigHashtype => ExecError::SchnorrSigHashtype,
            zulu_bitcoin_scriptexec::ExecError::SchnorrSig => ExecError::SchnorrSig,
            zulu_bitcoin_scriptexec::ExecError::TapscriptCheckMultiSig => {
                ExecError::TapscriptCheckMultiSig
            }
            zulu_bitcoin_scriptexec::ExecError::PubkeyCount => ExecError::PubkeyCount,
            zulu_bitcoin_scriptexec::ExecError::StackSize => ExecError::StackSize,
            zulu_bitcoin_scriptexec::ExecError::WitnessPubkeyType => ExecError::WitnessPubkeyType,
            zulu_bitcoin_scriptexec::ExecError::ScriptIntNumericOverflow => {
                ExecError::ScriptIntNumericOverflow
            }
            zulu_bitcoin_scriptexec::ExecError::Debug => ExecError::Debug,
        };
        Some(error)
    } else {
        None
    }
}
