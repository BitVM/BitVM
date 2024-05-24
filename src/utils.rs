use bitcoin_scriptexec::ExecError;
use test_bitcoin_scriptexec::ExecError as Test_ExecError;

pub fn test_exec_error_transform(error: Option<Test_ExecError>) -> Option<ExecError> {
    if let Some(err) = error.clone() {
        let error = match err {
            test_bitcoin_scriptexec::ExecError::DisabledOpcode => ExecError::DisabledOpcode,
            test_bitcoin_scriptexec::ExecError::OpCodeseparator => ExecError::OpCodeseparator,
            test_bitcoin_scriptexec::ExecError::BadOpcode => ExecError::BadOpcode,
            test_bitcoin_scriptexec::ExecError::OpCount => ExecError::OpCount,
            test_bitcoin_scriptexec::ExecError::PushSize => ExecError::PushSize,
            test_bitcoin_scriptexec::ExecError::MinimalData => ExecError::MinimalData,
            test_bitcoin_scriptexec::ExecError::InvalidStackOperation => {
                ExecError::InvalidStackOperation
            }
            test_bitcoin_scriptexec::ExecError::NegativeLocktime => ExecError::NegativeLocktime,
            test_bitcoin_scriptexec::ExecError::UnsatisfiedLocktime => {
                ExecError::UnsatisfiedLocktime
            }
            test_bitcoin_scriptexec::ExecError::UnbalancedConditional => {
                ExecError::UnbalancedConditional
            }
            test_bitcoin_scriptexec::ExecError::TapscriptMinimalIf => ExecError::TapscriptMinimalIf,
            test_bitcoin_scriptexec::ExecError::Verify => ExecError::Verify,
            test_bitcoin_scriptexec::ExecError::OpReturn => ExecError::OpReturn,
            test_bitcoin_scriptexec::ExecError::EqualVerify => ExecError::EqualVerify,
            test_bitcoin_scriptexec::ExecError::NumEqualVerify => ExecError::NumEqualVerify,
            test_bitcoin_scriptexec::ExecError::CheckSigVerify => ExecError::CheckSigVerify,
            test_bitcoin_scriptexec::ExecError::TapscriptValidationWeight => {
                ExecError::TapscriptValidationWeight
            }
            test_bitcoin_scriptexec::ExecError::PubkeyType => ExecError::PubkeyType,
            test_bitcoin_scriptexec::ExecError::SchnorrSigSize => ExecError::SchnorrSigSize,
            test_bitcoin_scriptexec::ExecError::SchnorrSigHashtype => ExecError::SchnorrSigHashtype,
            test_bitcoin_scriptexec::ExecError::SchnorrSig => ExecError::SchnorrSig,
            test_bitcoin_scriptexec::ExecError::TapscriptCheckMultiSig => {
                ExecError::TapscriptCheckMultiSig
            }
            test_bitcoin_scriptexec::ExecError::PubkeyCount => ExecError::PubkeyCount,
            test_bitcoin_scriptexec::ExecError::StackSize => ExecError::StackSize,
            test_bitcoin_scriptexec::ExecError::WitnessPubkeyType => ExecError::WitnessPubkeyType,
            test_bitcoin_scriptexec::ExecError::ScriptIntNumericOverflow => {
                ExecError::ScriptIntNumericOverflow
            }
            test_bitcoin_scriptexec::ExecError::Debug => ExecError::Debug,
        };
        Some(error)
    } else {
        None
    }
}
