use super::pushable;
use bitcoin_script::bitcoin_script as script;
use bitcoin::ScriptBuf as Script;

pub fn u16_add_carry() -> Script {
    script! {
        OP_ADD
        OP_DUP
        65535
        OP_GREATERTHAN
        OP_IF
            65536
            OP_SUB
            1
        OP_ELSE
            0
        OP_ENDIF
    }
}

pub fn u16_add() -> Script {
    script! {
        OP_ADD
        OP_DUP
        65535
        OP_GREATERTHAN
        OP_IF
            65536
            OP_SUB
        OP_ENDIF
    }
}
