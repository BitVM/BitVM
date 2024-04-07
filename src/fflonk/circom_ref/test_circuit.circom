pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

template Main() {
    signal input in[256]; // private

    signal output out_1;
    signal output out_2;

    component sha256 = Sha256(256);
    sha256.in <== in;

    component b2n_1 = Bits2Num(128);
    for(var i = 0; i < 128; i++) {
        b2n_1.in[i] <== sha256.out[i];
    }
    out_1 <== b2n_1.out;

    component b2n_2 = Bits2Num(128);
    for(var i = 0; i < 128; i++) {
        b2n_2.in[i] <== sha256.out[128 + i];
    }
    out_2 <== b2n_2.out;
}

component main = Main();