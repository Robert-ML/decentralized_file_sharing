// SPDX-License-Identifier: MIT


pragma solidity >=0.8.28;


import "./crypto_datamodel.sol";


// ----------------------------------------------------------------------------
// Registered file owners
// ----------------------------------------------------------------------------

struct PendingRegistrations {
    mapping (address => bool) pending_addresses;

    address[] addresses;
    mapping (address => uint) address_index;
}

// Track what users were registered to the contract as file uploaders and store
// their associated public keys for which the private key is known by the DPCN.
struct RegisteredFileOwnerTracker {
    mapping (address => bool) registered;
    mapping (address => uint) dpcn_pks;
}


// ----------------------------------------------------------------------------
// Stored files
// ----------------------------------------------------------------------------

// Fully uploaded files
struct FileUploaded {
    uint file_id; // unique file identifier
    address owner; // who requested the file id

    string file_info; // information about the file like name or anything
    string file_address; // where the encrypted file is stored

    // file's symmetric encryption key encrypted using the owner's public key
    EncryptedSymmetricKey owner_accessible_sym_key;
    // file's symmetric encryption key encrypted using the owners's associated DPCN public key
    EncryptedSymmetricKey dpcn_accessible_sym_key;
}

struct StoredFiles {
    mapping (uint => FileUploaded) file_id_data;

    // file_id -> used
    mapping (uint => bool) used_file_ids;
}


// ----------------------------------------------------------------------------
// File to be shared
// ----------------------------------------------------------------------------
struct ClientShareRequest {
    address client; // the initiator of the request
    uint file_id;
}

// Pending requests for a file's re-encryption key to be obtained
struct PendingShare {
    ClientShareRequest[] requests;

    // client_id -> file_id -> index
    mapping (address => mapping (uint => uint)) client_file_requests_index;

    // client_id -> file_id -> was requested?
    mapping (address => mapping (uint => bool)) client_file_requested;
}


// ----------------------------------------------------------------------------
// Shared files
// ----------------------------------------------------------------------------

struct SharedFileInfo {
    uint file_id;
    address client;

    // file's symmetric encryption key encrypted using the client's public key
    EncryptedSymmetricKey client_accessible_sym_key;
}

// Store the information about the shared files:
struct FilesShared {
    // clients -> file_id -> shared file data
    mapping (address => mapping (uint => SharedFileInfo)) clients;
    // clients -> file_id -> if shared or not
    mapping (address => mapping (uint => bool)) files;
}
