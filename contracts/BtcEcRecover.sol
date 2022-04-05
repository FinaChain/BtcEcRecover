pragma solidity ^0.4.26;
import {ECCMath} from "./lib/crypto/ECCMath.sol";
import {Secp256k1} from "./lib/crypto/Secp256k1.sol";

contract BtcEcRecover {
    uint256 constant p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    uint256 constant n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 constant gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    uint256 constant gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
    
    function recover(bytes32 hash, bytes memory signature) public view returns (bytes memory) {
        if (signature.length != 65) {
            return "";
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            v := byte(0, mload(add(signature, 0x20)))
            r := mload(add(signature, 0x21))
            s := mload(add(signature, 0x41))
        }
        if (uint256(s) > n / 2) {
            return "";
        }
        if (v != 27 && v != 28 && v != 31 && v != 32) {
            return "";
        }
        return btc_ecrecover(hash, v, r, s);
    }
    function btc_ecrecover(bytes32 msgh, uint8 v, bytes32 r, bytes32 s) private view returns (bytes memory) {
        uint i = 0;
        uint256 rr = uint256(r);
        uint256 ss = uint256(s);
        bool isYOdd = ((v - 27) & 1) != 0;
        bool isSecondKey = ((v - 27) & 2) != 0;
        bool isCompressed = ((v - 27) & 4) != 0;
        if (!isCompressed) {
            return "";
        }

        if (rr >= p % n && isSecondKey) {
            return "";
        }

        uint256[3] memory P = _getPoint(uint256(msgh), rr, ss, isYOdd, isSecondKey);
        if (P[2] == 0) {
            return "";
        }
        
        ECCMath.toZ1(P, p);
        bytes memory publicKey = new bytes(33);
        publicKey[0] = byte(P[1] % 2 == 0 ? 2 : 3);
        for (i = 0; i < 32; ++i) {
            publicKey[32 - i] = byte((P[0] >> (8 * i)) & 0xff);
        }
        return publicKey;
    }
    function _getPoint(uint256 msgh, uint256 r, uint256 s, bool isYOdd,bool isSecondKey) internal view returns (uint256[3] memory) {
        uint256 rx = isSecondKey ? r + n : r;
        uint256 ry = ECCMath.expmod(ECCMath.expmod(rx, 3, p) + 7, p / 4 + 1, p);
        if (isYOdd != (ry % 2 == 1)) {
            ry = p - ry;
        }
        uint256 invR = ECCMath.invmod(r, n);
        return Secp256k1._add(
            Secp256k1._mul(n - mulmod(msgh, invR, n), [gx, gy]),
            Secp256k1._mul(mulmod(s, invR, n), [rx, ry]));
    }
}