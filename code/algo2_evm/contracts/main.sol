// SPDX-License-Identifier: MIT

pragma solidity >=0.8.28;

import "./datamodel.sol";
import "./crypto_datamodel.sol";

contract Algo2ProxyReencryption {
    // prime number the elliptic curves are in
    uint256 constant p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;


    mapping (uint => bool) used_request_ids;

    FilesPendingIDRequest private user_file_id_reqs;

    FilesPendingUpload private files_pending_upload;

    StoredFiles private stored_files;

    PendingReencryption private re_enc_reqs;

    FilesShared private shared_files;

// ----------------------------------------------------------------------------
// Access Methods to request file upload, service and retrieve the response credentials
// ----------------------------------------------------------------------------
    function request_file_upload_info(address user, uint request_id) public {
        /**
         * Clients transact this method to request credentials for a file they want to upload
         *
         * @param user: the client's public ERC20 address
         * @param request_id: a request ID for the user to identify the request when the credentials become available
         */
        RequestForFileId memory file_request = RequestForFileId(user, request_id);

        require(used_request_ids[request_id] == false, "Request ID already used");
        require(user_file_id_reqs.used_request_ids[user][request_id] == false, "Request ID in use by user already used");

        if (user_file_id_reqs.data[user].length == 0) {
            user_file_id_reqs.requesters.push(user);
        }

        user_file_id_reqs.data[user].push(file_request);
        user_file_id_reqs.used_request_ids[user][request_id] = true;

        // mark the request ID as used to not be user ever again
        used_request_ids[request_id] = true;
    }


    function get_users_pending_uploads() public view returns (address[] memory) {
        /**
         * DPCN Algo 2 calls this method periodically to check if there are users which have file upload requests for
         * credentials.
         */
        return user_file_id_reqs.requesters;
    }


    function get_files_pending_ids_of_user(address user) public view returns (uint[] memory) {
        /**
         * DPCN Algo 2 calls this method to check what file request ids the given user has
         *
         * @param user: the user in which the DPCN is interested if has file requests
         */
        uint no_pending_ids = user_file_id_reqs.data[user].length;
        uint[] memory request_ids = new uint[](no_pending_ids);

        for (uint i = 0; i < no_pending_ids; ++i) {
            request_ids[i] = user_file_id_reqs.data[user][i].request_id;
        }
        return request_ids;
    }

    function respond_with_file_id(
        uint request_id,
        uint generated_file_id,
        address user,
        uint[] memory pp_g,
        uint[] memory pp_g1,
        uint[] memory pp_h,
        uint[] memory pp_u_v_d,
        uint[] memory prenc_public_key_pk,
        uint[] memory prenc_secret_encrypted
    ) public {
        /**
         * DPCN Algo 2 transacts this method to respond with the file's credentials.
         *
         * @param request_id: the request id the user provided
         * @param generated_file_id: the file id to be used to uniquely identify the file
         * @param user: the user that initiated the request to upload the file
         * @param pp_g: public parameter g (generator in G2) as uint[] where the elements expected
         *  are: [g_00, g_01, g_10, g_11]
         * @param pp_g1: public parameter g1 (generator in G1) as uint[] where the elements expected are: [g1_0, g1_1]
         * @param pp_h: public parameter h (in G2) as uint[] where the elements expected
         *  are: [h_00, h_01, h_10, h_11]
         * @param pp_u_v_d: public parameters u, v, d (in G1) as uint[] where the elements expected
         *  are: [u_0, u_1, v_0, v_1, d_0, d_1]
         * @param prenc_public_key_pk: proxy re-encryption public key as uint[] where the elements expected
         *  are: [pk1_00, pk1_01, pk1_10, pk1_11, pk2_0, pk2_1, pk3_00, pk3_01, pk3_10, pk3_11]; pk1 in G2,
         *  pk2 in G1, pk3 in G2
         * @param prenc_secret_encrypted: proxy re-encryption secret key where the elements expected
         *  are: [sk1, sk2] (normally this would be encrypted and accessible only by the user with its private key)
         */
        // check if request exists
        require(user_file_id_reqs.used_request_ids[user][request_id] == true, "Unknown request_id was passed for the given user");

        // build the data
        PublicParameters memory public_parameters = PublicParameters({
            g_00: pp_g[0], g_01: pp_g[1],
            g_10: pp_g[2], g_11: pp_g[3],

            g1_0: pp_g1[0], g1_1: pp_g1[1],

            h_00: pp_h[0], h_01: pp_h[1],
            h_10: pp_h[2], h_11: pp_h[3],

            u_0: pp_u_v_d[0], u_1: pp_u_v_d[1],
            v_0: pp_u_v_d[2], v_1: pp_u_v_d[3],
            d_0: pp_u_v_d[4], d_1: pp_u_v_d[5]
        });

        PrencPublicKey memory prenc_public_key = PrencPublicKey({
            pk1_00: prenc_public_key_pk[0],
            pk1_01: prenc_public_key_pk[1],
            pk1_10: prenc_public_key_pk[2],
            pk1_11: prenc_public_key_pk[3],

            pk2_0: prenc_public_key_pk[4],
            pk2_1: prenc_public_key_pk[5],

            pk3_00: prenc_public_key_pk[6],
            pk3_01: prenc_public_key_pk[7],
            pk3_10: prenc_public_key_pk[8],
            pk3_11: prenc_public_key_pk[9]
        });

        PrencEncryptedForOwner memory encrypted_prenc_secret_key = PrencEncryptedForOwner({
            encrypted_prenc_secret_key_sk0: prenc_secret_encrypted[0],
            encrypted_prenc_secret_key_sk1: prenc_secret_encrypted[1]
        });

        FileEncryptionData memory encryption_data = FileEncryptionData({
            file_id: generated_file_id,
            owner: user,
            public_parameters: public_parameters,
            prenc_public_key: prenc_public_key,
            encrypted_prenc_secret_key: encrypted_prenc_secret_key
        });

        // store the data
        files_pending_upload.data[user][generated_file_id] = encryption_data;
        files_pending_upload.request_to_file_id[user][request_id] = generated_file_id;
        files_pending_upload.file_id_to_request[user][generated_file_id] = request_id;
        files_pending_upload.user_pending_files[user][request_id] = true;
        files_pending_upload.user_request_ids_pending[user].push(request_id);

        // clear the request
        _user_file_id_reqs_solve_request(request_id, user);
    }


    function get_user_files_pending_upload(address user) public view returns (uint[] memory) {
        /**
         * @dev Clients call this method to check what request_ids are ready to be serviced
         *
         * @param user: the user which requested the file and for which the file credentials were generated
         *
         * @return: a list with all request_ids that were serviced and are ready to have files uploaded for
         */
        return files_pending_upload.user_request_ids_pending[user];
    }

    function get_request_id_result(address user, uint request_id) public view returns (uint[19] memory return_data) {
        /**
         * @dev Clients call this method to retrieve the file credentials generated by a certain request_id
         *
         * @param user: the user for which the file credentials were generated
         * @param request_id: user's generated request ID used initially to request the file's credentials generation
         *
         * @return: a list of uint's composed of 20 elements: [
         *  generated_file_id: the file id to be used to uniquely identify the file from now, and find its credentials,
         *  pp_g: 4 elements of public parameter g (generator in G2) as: [g_00, g_01, g_10, g_11],
         *  pp_g1: 2 elements of public parameter g1 (generator in G1) as: [g1_0, g1_1],
         *  pp_h: 4 elements of public parameter h (generator in G2) as: [h_00, h_01, h_10, h_11],
         *  pp_u: 2 elements of public parameter u (generator in G1) as: [u_0, u_1],
         *  pp_v: 2 elements of public parameter v (generator in G1) as: [v_0, v_1],
         *  pp_d: 2 elements of public parameter d (generator in G1) as: [d_0, d_1],
         *  prenc_secret_encrypted: for simplicity the secret key numbers as: [sk1, sk2]
         * ]
         */
        require(files_pending_upload.user_pending_files[user][request_id] == true, "Request ID of user does not point to any file credentials");

        uint generated_file_id = files_pending_upload.request_to_file_id[user][request_id];
        require(generated_file_id == files_pending_upload.data[user][generated_file_id].file_id, "Logic error in the contract, generated file id does not match in structure");

        return_data[0] = generated_file_id;

        return_data[1] = files_pending_upload.data[user][generated_file_id].public_parameters.g_00;
        return_data[2] = files_pending_upload.data[user][generated_file_id].public_parameters.g_01;
        return_data[3] = files_pending_upload.data[user][generated_file_id].public_parameters.g_10;
        return_data[4] = files_pending_upload.data[user][generated_file_id].public_parameters.g_11;

        return_data[5] = files_pending_upload.data[user][generated_file_id].public_parameters.g1_0;
        return_data[6] = files_pending_upload.data[user][generated_file_id].public_parameters.g1_1;

        return_data[7] = files_pending_upload.data[user][generated_file_id].public_parameters.h_00;
        return_data[8] = files_pending_upload.data[user][generated_file_id].public_parameters.h_01;
        return_data[9] = files_pending_upload.data[user][generated_file_id].public_parameters.h_10;
        return_data[10] = files_pending_upload.data[user][generated_file_id].public_parameters.h_11;

        return_data[11] = files_pending_upload.data[user][generated_file_id].public_parameters.u_0;
        return_data[12] = files_pending_upload.data[user][generated_file_id].public_parameters.u_1;

        return_data[13] = files_pending_upload.data[user][generated_file_id].public_parameters.v_0;
        return_data[14] = files_pending_upload.data[user][generated_file_id].public_parameters.v_1;

        return_data[15] = files_pending_upload.data[user][generated_file_id].public_parameters.d_0;
        return_data[16] = files_pending_upload.data[user][generated_file_id].public_parameters.d_1;

        return_data[17] = files_pending_upload.data[user][generated_file_id].encrypted_prenc_secret_key.encrypted_prenc_secret_key_sk0;
        return_data[18] = files_pending_upload.data[user][generated_file_id].encrypted_prenc_secret_key.encrypted_prenc_secret_key_sk1;

        return return_data;
    }

    function upload_file(address user, uint file_id, string memory file_info, string memory file_address, uint[23] memory cyphertext) public {
        /**
         * @dev Clients transact this method to upload a file's cyphertext and some metadata about it.
         *
         * @param user: the user which initiated the file upload request
         * @param file_id: the file id of the credentials generated by the DPCN
         * @param file_info: metadata to be kept alongside the file
         * @param file_address: should be any string that helps for the encrypted file to be found as a resource
         * @param cyphertext: the encrypted file, in practice the encrypted symmetric key used to encrypt the file
         */

        uint request_id = files_pending_upload.file_id_to_request[user][file_id];
        require(files_pending_upload.user_pending_files[user][request_id] == true, "File ID passed does not reference a valid pending file for upload for the user");

        FileEncryptionData memory encryption_data = files_pending_upload.data[user][file_id];
        PrencCyphertext memory cyphertext_object = PrencCyphertext(cyphertext);

        FileUploaded memory stored_file = FileUploaded({
            encryption_data: encryption_data,
            file_info: file_info,
            file_address: file_address,
            cyphertext: cyphertext_object
        });

        // store the file
        stored_files.cloud[user][file_id] = stored_file;
        stored_files.users_files[user].push(file_id);
        stored_files.user_file_id_exists[user][file_id] = true;

        // remove the file from pending files pending to be uploaded
        _remove_file_from_pending_upload(user, file_id);
    }


// ----------------------------------------------------------------------------
// Access Methods to request file share, service and retrieve the re-encryption key
// ----------------------------------------------------------------------------

    function request_file_share(address client, uint[] memory client_prenc_pk, address file_owner, uint file_id) public {
        /**
         * Clients who want a file to be shared to them call this function to start the sharing process.
         *
         * @param client: address of the client who wants the file shared
         * @param client_prenc_pk: proxy re-encryption public key (secret key known by the client) as uint[] where the
         *  elements expected are: [pk1_00, pk1_01, pk1_10, pk1_11, pk2_0, pk2_1, pk3_00, pk3_01, pk3_10, pk3_11]; pk1
         *  in G2, pk2 in G1, pk3 in G2
         * @param file_owner: address of the owner of the file
         * @param file_id: unique identifier of the file that we want to be shared
         */
        // check the file actually exists
        require(stored_files.user_file_id_exists[file_owner][file_id] == true, "File Owner Address and File ID pair does not reference an uploaded file.");

        PrencPublicKey memory prenc_pk = PrencPublicKey({
            pk1_00: client_prenc_pk[0],
            pk1_01: client_prenc_pk[1],
            pk1_10: client_prenc_pk[2],
            pk1_11: client_prenc_pk[3],

            pk2_0: client_prenc_pk[4],
            pk2_1: client_prenc_pk[5],

            pk3_00: client_prenc_pk[6],
            pk3_01: client_prenc_pk[7],
            pk3_10: client_prenc_pk[8],
            pk3_11: client_prenc_pk[9]
        });

        ClientShareRequest memory share_request = ClientShareRequest({
            file_owner: file_owner,
            file_id: file_id,
            client: client,
            client_prenc_pk: prenc_pk
        });

        re_enc_reqs.requests.push(share_request);
        re_enc_reqs.client_file_requests[client][file_id] = share_request;
    }

    function get_pending_share_requests() public view returns (address[] memory, address[] memory, uint[] memory, uint[] memory) {
        /**
         * DPCN Algo 2 calls this method periodically to check what file share requests are pending in the EVM.
         *
         * @return: lists of elements that construct the individual requests
         * - client address (1 entry)
         * - file owner address (1 entry)
         * - file id (1 entry)
         * - proxy re-encryption public key of the client (10 entries)
         *
         * Example: for 2 requests, the sizes of the returned array sizes are: (2, 2, 2, 20)
         */

        uint no_pending_share_reqs = re_enc_reqs.requests.length;
        address[] memory ret_client_addresses = new address[](no_pending_share_reqs);
        address[] memory ret_file_owner_addresses = new address[](no_pending_share_reqs);
        uint[] memory ret_file_ids = new uint[](no_pending_share_reqs);
        uint[] memory ret_client_prenc_pks = new uint[](no_pending_share_reqs * 10);

        for (uint i = 0; i < no_pending_share_reqs; ++i) {
            ret_client_addresses[i] = re_enc_reqs.requests[i].client;
            ret_file_owner_addresses[i] = re_enc_reqs.requests[i].file_owner;
            ret_file_ids[i] = re_enc_reqs.requests[i].file_id;

            ret_client_prenc_pks[i * 10 + 0] = re_enc_reqs.requests[i].client_prenc_pk.pk1_00;
            ret_client_prenc_pks[i * 10 + 1] = re_enc_reqs.requests[i].client_prenc_pk.pk1_01;
            ret_client_prenc_pks[i * 10 + 2] = re_enc_reqs.requests[i].client_prenc_pk.pk1_10;
            ret_client_prenc_pks[i * 10 + 3] = re_enc_reqs.requests[i].client_prenc_pk.pk1_11;

            ret_client_prenc_pks[i * 10 + 4] = re_enc_reqs.requests[i].client_prenc_pk.pk2_0;
            ret_client_prenc_pks[i * 10 + 5] = re_enc_reqs.requests[i].client_prenc_pk.pk2_1;

            ret_client_prenc_pks[i * 10 + 6] = re_enc_reqs.requests[i].client_prenc_pk.pk3_00;
            ret_client_prenc_pks[i * 10 + 7] = re_enc_reqs.requests[i].client_prenc_pk.pk3_01;
            ret_client_prenc_pks[i * 10 + 8] = re_enc_reqs.requests[i].client_prenc_pk.pk3_10;
            ret_client_prenc_pks[i * 10 + 9] = re_enc_reqs.requests[i].client_prenc_pk.pk3_11;
        }

        return (ret_client_addresses, ret_file_owner_addresses, ret_file_ids, ret_client_prenc_pks);
    }

    function respond_with_re_encryption_key(
        address client,
        uint file_id,
        uint[2] memory re_enc_key
    ) public {
        /**
         * DPCN Algo 2 transacts this method to respond with the generated re-encryption key which is associated with
         * a share request for the client on the file_id.
         *
         * @param client: address of the client who wants the file shared
         * @param file_id: unique identifier of the file was requested to be shared
         * @param re_enc_key: generated re-encryption key which is an element in G1 (2 uint elements)
         */

        // check the request was actually made
        ClientShareRequest memory share_request = re_enc_reqs.client_file_requests[client][file_id];
        require(share_request.file_id == file_id && share_request.client == client, "Re-encryption key response is not associated with a share request.");
        require(stored_files.user_file_id_exists[share_request.file_owner][file_id] == true, "File requested to be shared is no longer uploaded / available.");

        // retrieve the file data and construct the re-encryption key structure
        FileUploaded memory file_data = stored_files.cloud[share_request.file_owner][file_id];
        PrencReencryptionKey memory constructed_re_enc_key = PrencReencryptionKey({
            renc_0: re_enc_key[0],
            renc_1: re_enc_key[1]
        });

        // check the validity of the re-encryption key
        bool re_key_checks_out = _check_re_encryption_key(
            constructed_re_enc_key,
            [
                file_data.encryption_data.prenc_public_key.pk1_00,
                file_data.encryption_data.prenc_public_key.pk1_01,
                file_data.encryption_data.prenc_public_key.pk1_10,
                file_data.encryption_data.prenc_public_key.pk1_11
            ],
            [
                share_request.client_prenc_pk.pk2_0,
                share_request.client_prenc_pk.pk2_1
            ],
            [
                file_data.encryption_data.public_parameters.g_00,
                file_data.encryption_data.public_parameters.g_01,
                file_data.encryption_data.public_parameters.g_10,
                file_data.encryption_data.public_parameters.g_11
            ]
        );
        if (re_key_checks_out == false) {
            // the check failed but still remove the share request even if it was not serviced correctly
            _remove_file_share_pending_request(client, file_id);
            require(false, "Re-encryption key verification failed, it is considered invalid!");
        }

        // store the re-encryption key
        FileReencryptionInformation memory shared_file_info = FileReencryptionInformation({
            file_id: file_id,
            owner: share_request.file_owner,
            client: client,
            re_encryption_key: constructed_re_enc_key,
            owner_prenc_public_key: file_data.encryption_data.prenc_public_key,
            client_prenc_public_key: share_request.client_prenc_pk
        });
        shared_files.clients[client][file_id] = shared_file_info;
        shared_files.files[client][file_id] = true;

        // remove the share request
        _remove_file_share_pending_request(client, file_id);
    }

    function get_file_share_result(address client, uint file_id) public view returns (bool, uint[2] memory re_enc_key) {
        /**
         * Method to be called to obtain the re-encryption key for a file share request if it was submitted and
         * processed.
         *
         * @param client: the client that initiated the file share request
         * @param field_id: the id of the file which was shared
         *
         * @return: a tuple of the call result, the first element is a bool representing if the call succeeded and the
         * second is a 2 element array containing the re-encryption key (valid only if the call succeeded)
         */
        // the file was not shared for this user
        if (shared_files.files[client][file_id] != true) {
            return (false, re_enc_key);
        }

        FileReencryptionInformation memory shared_file_info = shared_files.clients[client][file_id];
        re_enc_key[0] = shared_file_info.re_encryption_key.renc_0;
        re_enc_key[1] = shared_file_info.re_encryption_key.renc_1;

        return (true, re_enc_key);
    }

// ----------------------------------------------------------------------------
// Constructor
// ----------------------------------------------------------------------------
    constructor () {}


// ----------------------------------------------------------------------------
// Helper methods
// ----------------------------------------------------------------------------
    function _user_file_id_reqs_solve_request(uint request_id, address user) private {
        require(user_file_id_reqs.used_request_ids[user][request_id] == true, "Can not solve request as request_id of user was considered not used");

        RequestForFileId[] storage user_requests = user_file_id_reqs.data[user];
        uint no_current_requesters = user_file_id_reqs.requesters.length;
        uint no_user_requests = user_requests.length;

        for (uint i = 0; i < no_user_requests; ++i) {
            if (user_requests[i].request_id != request_id) {
                continue;
            }
            // found the index at which the request_id is present
            user_requests[i] = user_requests[no_user_requests - 1];
            user_requests.pop();

            break;
        }
        delete user_file_id_reqs.used_request_ids[user][request_id];

        // check if the user has any remaining requests
        if (user_requests.length != 0) {
            return;
        }

        // if not, delete his entry and the user from the list of users with pending requests
        delete user_file_id_reqs.data[user];

        for (uint i = 0; i < no_current_requesters; ++i) {
            if (user_file_id_reqs.requesters[i] != user) {
                continue;
            }
            // found the user's entry in the requesters list
            user_file_id_reqs.requesters[i] = user_file_id_reqs.requesters[no_current_requesters - 1];
            user_file_id_reqs.requesters.pop();

            break;
        }
    }

    function _remove_file_from_pending_upload(address user, uint file_id) private {
        uint request_id = files_pending_upload.file_id_to_request[user][file_id];
        require(files_pending_upload.user_pending_files[user][request_id] == true, "File ID passed for removal from pending files to upload does not reference a valid entry for the user");

        delete files_pending_upload.data[user][file_id];
        delete files_pending_upload.request_to_file_id[user][request_id];
        delete files_pending_upload.file_id_to_request[user][file_id];
        delete files_pending_upload.user_pending_files[user][request_id];

        uint[] storage user_requests_pending = files_pending_upload.user_request_ids_pending[user];
        uint no_user_requests_pending = user_requests_pending.length;

        for (uint i = 0; i < no_user_requests_pending; ++i) {
            if (files_pending_upload.user_request_ids_pending[user][i] != request_id) {
                continue;
            }
            // found the index at which the request_id is present
            user_requests_pending[i] = user_requests_pending[no_user_requests_pending - 1];
            user_requests_pending.pop();

            break;
        }
    }

    function _check_re_encryption_key(PrencReencryptionKey memory re_key, uint[4] memory owner_prenc_pk1, uint[2] memory client_prenc_pk2, uint[4] memory generator_g) private view returns (bool) {
        /**
         * Check with the pairing of elliptic curves precompile the formula: e(pki_1, re_key) == e(g, pkj_2)
         * @param re_key: re-encryption key in G2
         * @param owner_prenc_pk1: first element of the proxy re-encryption public key which is in G1
         * @param client_prenc_pk2: second element of the proxy re-encryption public key which is in G2
         * @param generator_g: the chosen generator from the public parameters which is an element in G1
         *
         * @return: true if the pairing checks out
         */
        // verification, precompile input:
        // - re_key.x
        // - re_key.y
        // - pki_1.x_imaginary
        // - pki_1.x_real
        // - pki_1.y_imaginary
        // - pki_1.y_real
        // - pkj_2.x
        // - (p - pkj_2.y) % p
        // - g.x_imaginary
        // - g.x_real
        // - g.y_imaginary
        // - g.y_real
        // TODO: check the order is fine, not suer about the imaginary part coming before the real part
        uint256[12] memory input = [
            re_key.renc_0, re_key.renc_1,
            owner_prenc_pk1[1], owner_prenc_pk1[0], owner_prenc_pk1[3], owner_prenc_pk1[2],
            client_prenc_pk2[0], (p - client_prenc_pk2[1]) % p,
            generator_g[1], generator_g[0], generator_g[3], generator_g[2]
        ];
        uint input_size = input.length * 32;
        uint[1] memory output;

        assembly {
            if iszero(staticcall(gas(), 8, input, input_size, output, 0x20)) {
                revert(0, 0)
            }
        }

        // TODO: check the precompile returns 1 if all is fine
        return output[0] == 1;
    }

    function _remove_file_share_pending_request(address client, uint file_id) private {

        ClientShareRequest[] storage share_requests = re_enc_reqs.requests;
        uint no_share_requests = share_requests.length;

        for (uint i = 0; i < no_share_requests; ++i) {
            if (share_requests[i].client != client || share_requests[i].file_id != file_id) {
                continue;
            }
            // found the index at which the request_id is present
            share_requests[i] = share_requests[no_share_requests - 1];
            share_requests.pop();

            break;
        }

        delete re_enc_reqs.client_file_requests[client][file_id];
    }
}
