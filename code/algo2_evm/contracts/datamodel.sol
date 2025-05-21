// SPDX-License-Identifier: MIT

pragma solidity >=0.8.28;

import "./crypto_datamodel.sol";


// ----------------------------------------------------------------------------
// File to be uploaded
// ----------------------------------------------------------------------------
struct RequestForFileId {
    address user;
    uint request_id; // for the user to track his requests
}

// Users request FileIDs and the requests are put in here for future reference when the DPCN sends them
struct FilesPendingIDRequest {
    mapping (address => RequestForFileId[]) data;
    mapping (address => mapping (uint => bool)) used_request_ids;
    address[] requesters; // equal to data.keys()
    // could be optimized with a mapping to get easier the indexes of each requester
}

// File pending to be uploaded has data provided by the DPCN
struct FileEncryptionData {
    uint file_id;
    address owner; // who requested the file id
    PublicParameters public_parameters;
    PrencPublicKey prenc_public_key;
    PrencEncryptedForOwner encrypted_prenc_secret_key; // accessible only by the owner
}

struct FilesPendingUpload {
    // user_id -> file_id -> file data to upload
    mapping (address => mapping (uint => FileEncryptionData)) data;
    mapping (address => mapping (uint => uint)) request_to_file_id;
    mapping (address => mapping (uint => uint)) file_id_to_request;

    // user_id -> request_ids
    // to easily and efficiently check if the request_id was serviced and is pending
    mapping (address => mapping (uint => bool)) user_pending_files;
    // to quickly check what requests are ready for upload by the user
    mapping (address => uint[]) user_request_ids_pending;
}


// ----------------------------------------------------------------------------
// Stored files
// ----------------------------------------------------------------------------

// Fully uploaded files
struct FileUploaded {
    FileEncryptionData encryption_data;

    string file_info; // information about the file like name or anything
    string file_address; // where the encrypted file is stored

    PrencCyphertext cyphertext;
}

struct StoredFiles {
    // user -> file_id -> file data
    mapping (address => mapping (uint => FileUploaded)) cloud;

    // user_id -> file_ids (list of all files stored per user)
    mapping (address => uint[]) users_files;
    // user_id -> file_id -> ?used
    mapping (address => mapping (uint => bool)) user_file_id_exists;
}


// ----------------------------------------------------------------------------
// File to be shared
// ----------------------------------------------------------------------------
struct ClientShareRequest {
    uint file_id;
    address client_id; // the initiator of the request
    PrencPublicKey prenc_public_key;
}

// Pending requests for a file's re-encryption key to be obtained
struct PendingReencryption {
    ClientShareRequest[] requests;
}


// ----------------------------------------------------------------------------
// Stored files
// ----------------------------------------------------------------------------

struct FileReencryptionInformation {
    uint file_id;
    address owner;
    address client;
    PrencReencryptionKey reencryption_key;
    PrencPublicKey owner_prenc_public_key;
    PrencPublicKey client_prenc_public_key;
}

// Store the information about:
// - the clients and what files they have shared access to
// - the files and who has access to them
struct FilesShared {
    // clients -> shared files -> shared file data
    mapping (address => mapping (uint => FileReencryptionInformation)) clients;
    // shared files -> clients -> if shared or not
    mapping(uint => mapping (address => bool)) files;
}
