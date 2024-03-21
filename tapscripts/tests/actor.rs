
use tapscripts::actor::{Actor, Player};

pub fn test_player() -> Player {
    Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398")
}

#[test]
fn test_preimage() {
    let player = test_player();
    let preimage = player.preimage("TRACE_RESPONSE_0_5_byte0", Some(3), 3);

    assert_eq!(
        hex::encode(preimage),
        "7e85b1014de4146f534005c74f309220fe8a5a3c"
    )
}
