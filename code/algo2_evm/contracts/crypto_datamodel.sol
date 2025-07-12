// SPDX-License-Identifier: MIT

pragma solidity >=0.8.28;

struct PrencEncryptedForOwner {
    uint encrypted_prenc_secret_key_sk0;
    uint encrypted_prenc_secret_key_sk1;
}

struct PublicParameters {
    // generator in G2
    uint g_00;
    uint g_01;
    uint g_10;
    uint g_11;

    // generator in G1
    uint g1_0;
    uint g1_1;

    // in G2
    uint h_00;
    uint h_01;
    uint h_10;
    uint h_11;

    // in G1
    uint u_0;
    uint u_1;

    // in G1
    uint v_0;
    uint v_1;

    // in G1
    uint d_0;
    uint d_1;
}

struct PrencPublicKey {
    // in G2
    uint pk1_00;
    uint pk1_01;
    uint pk1_10;
    uint pk1_11;

    // in G1
    uint pk2_0;
    uint pk2_1;

    // in G2
    uint pk3_00;
    uint pk3_01;
    uint pk3_10;
    uint pk3_11;
}

struct PrencReencryptionKey {
    // in G1
    uint renc_0;
    uint renc_1;
}


// cyphertext of the symmetric key, good for direct decryption or re-encryption (obtained by algorithm ENC2)
struct PrencCyphertext {
    uint[23] data;
}


// cyphertext resulting from:
// - output of algorithm ENC1;
// - re-encryption of the `CyphertextToBeReencrypted` object and applying a re-encryption key;
// with valid public parameters
// NOTE: not used (as re-encryption does not happen on blockchain)
struct CyphertextReencrypted {
    uint[8] A_n_B;
    bytes C;
    bytes C_iv;
}
