// contracts/GameItem.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract SecureEstate is ERC721URIStorage {
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;
    constructor() ERC721("SecureEstate", "SETT") {}

    bool status_contract = false;
    bool status_payment = false;

    // 1. Hash Verification Process:
    //seller hashes the contract details:
    function hash_seller(string memory contract_details) public pure returns(bytes32){ 
        return keccak256(abi.encodePacked(contract_details));
    }

    //buyer hashes the contract details received from the seller:
    function hash_buyer(string memory contract_details) public pure returns(bytes32){ 
        return keccak256(abi.encodePacked(contract_details));
    }

    //buyer verifies the hashes match:
    function verify_hashCont (bytes32 buyer_hash, bytes32 seller_hash) public pure returns (bool){
        if (buyer_hash == seller_hash){
            return true;
        } else {
            return false;
        }
    }

    //store the result
    function assignC(bytes32 buyer_hash, bytes32 seller_hash) public {
        status_contract = verify_hashCont(buyer_hash, seller_hash);
    } //(OpenAI, 2023)

    // 2. Payment verification process:
    //buyer hash the payment details:
    function hash_paymentB (string memory name_on_card, int256 amount) public pure returns (bytes32){
        return keccak256(abi.encodePacked(name_on_card, amount));
    }

    //seller receives the hash and the payment details, this verifies the transaction:
    function hash_paymentS (string memory name_on_card, int256 amount) public pure returns (bytes32){
        return keccak256(abi.encodePacked(name_on_card, amount));
    }

    //seller verifies the hashes match and manually aknowledges the receipt of payment:
    function verify_hashPayment (bytes32 pay_hashB, bytes32 pay_hashS, string memory aknowledegement_of_payment) public pure returns(bool, bytes32){
        if (pay_hashB == pay_hashS && keccak256(abi.encodePacked(aknowledegement_of_payment)) == keccak256(abi.encodePacked("Payment Received"))) {
            bytes32 combined_hash = keccak256(abi.encodePacked(pay_hashS, pay_hashB, aknowledegement_of_payment));
            return (true, combined_hash);
        } else {
            return (false, bytes32(0));
        }
    }
    
    //store the result
    function assignP(bytes32 pay_hashB, bytes32 pay_hashS, string memory aknowledegement_of_payment) public {
        (bool Ver, ) = verify_hashPayment(pay_hashB, pay_hashS, aknowledegement_of_payment);
        status_payment = Ver;
    } //(OpenAI, 2023)

    // 3. Generate NFT

    //generate URI 
    ///
    // Function to convert bytes32 to a hex string
    function bytes32ToHexString(bytes32 data) public pure returns (string memory) {
    bytes memory alphabet = "0123456789abcdef";
    bytes memory str = new bytes(64); // A bytes32 value will result in a 64-character hex string

    for (uint256 i = 0; i < 32; i++) {
        str[2*i] = alphabet[uint8(data[i] >> 4)]; // Get the first 4 bits
        str[2*i+1] = alphabet[uint8(data[i] & 0x0f)]; // Get the last 4 bits
    }

    return string(str);
    }
    ///(ChatGPT, 2023)

    // define function that generates the URI if the hashes are verified:
    function generateURI(bytes32 cont_ver_hash, bytes32 pay_ver_hash) public pure returns (string memory) {
    
    //convert to hexadecimal string
    string memory cont_hash_hex = bytes32ToHexString(cont_ver_hash);  
    string memory pay_hash_hex = bytes32ToHexString(pay_ver_hash);

    //generate URI
    string memory uri = string(abi.encodePacked("https://SecureEstate.com/contractHash=", cont_hash_hex,"&paymentHash=", pay_hash_hex));
    return uri;
    }

    // contract_ver_Hash will have to be provided by the buyer
    // payment_ver_Hash will have to be provided by the seller
    
    //generate the NFT only if the hashes are verified:
    //the NFT function will be on the seller side, but the seller will only be able to provide the payment hash.
    function awardItem(address buyer_wallet_address, bytes32 cont_ver_hash, bytes32 pay_ver_hash) public returns (uint){
        
        ///
        require(status_contract, "Contract hash not verified");
        require(status_payment , "Payment hash not verified");
        /// (ChatGPT, 2023)
        
        //generate the URI if true
        string memory uri = generateURI(cont_ver_hash, pay_ver_hash);

        //mint the NFT
        uint256 newItemId = _tokenIds.current(); 
        _mint(buyer_wallet_address, newItemId); 
        _setTokenURI(newItemId, uri);

        _tokenIds.increment();

        //token ID of the new NFT
        return newItemId;
        }
}