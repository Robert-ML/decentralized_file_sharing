// SPDX-License-Identifier: MIT

pragma solidity >=0.8.28;

import "./datamodel.sol";
import "./crypto_datamodel.sol";

contract Algo2ProxyReencryption {
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


    // TODO: request re-enc
    // TODO: upload re-enc info for file
    // TODO: retrieve upload info

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
}
