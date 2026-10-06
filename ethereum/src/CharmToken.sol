// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ICharmToken, ICharmTokenHooks, ICharmsLedger, ICharmsTypes} from "./interfaces/ICharms.sol";
import {appKey} from "./libraries/CharmTokenClone.sol";

/// @notice The shared implementation behind every tag-`t` `CharmToken` clone. Each clone appends
/// its packed `App` (68 bytes) and that length as a `uint16` to the calldata of every call, then
/// `delegatecall`s here, so storage below belongs to the clone.
/// @dev Holds allowances and permit nonces. Balances, supply, metadata, and every transfer rule
/// live in `Charms`, which can be upgraded while this code cannot: it is part of `tokenAddress`.
contract CharmToken is ICharmToken, ICharmTokenHooks {
    bytes32 private constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant APP_ARGS_LENGTH = 70;

    /// @notice The Charms proxy. It deploys this implementation, so it is `msg.sender` here.
    ICharmsLedger public immutable charms;

    mapping(address owner => mapping(address spender => uint256)) public allowance;
    mapping(address owner => uint256) public nonces;

    constructor() {
        charms = ICharmsLedger(msg.sender);
    }

    function app() public pure returns (ICharmsTypes.App memory a) {
        assembly ("memory-safe") {
            let args := sub(calldatasize(), APP_ARGS_LENGTH)
            mstore(a, shr(224, calldataload(args)))
            mstore(add(a, 0x20), calldataload(add(args, 4)))
            mstore(add(a, 0x40), calldataload(add(args, 36)))
        }
    }

    function totalSupply() external view returns (uint256) {
        return charms.totalSupply(_appKey());
    }

    function balanceOf(address owner) external view returns (uint256) {
        return charms.balanceOf(_appKey(), owner);
    }

    function name() public view returns (string memory) {
        return charms.name(app());
    }

    function symbol() external view returns (string memory) {
        return charms.symbol(app());
    }

    function decimals() external view returns (uint8) {
        return charms.decimals(app());
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        charms.tokenTransfer(app(), msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert InsufficientAllowance();
            allowance[from][msg.sender] = allowed - amount;
        }
        charms.tokenTransfer(app(), from, to, amount);
        return true;
    }

    function emitTransfer(address from, address to, uint256 amount) external {
        if (msg.sender != address(charms)) revert NotCharms();
        emit Transfer(from, to, amount);
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (block.timestamp > deadline) revert PermitExpired();
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR(), structHash);
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, s);
        if (err != ECDSA.RecoverError.NoError || signer != owner) revert InvalidSigner();
        _approve(owner, spender, value);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name())),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function _approve(address owner, address spender, uint256 amount) private {
        allowance[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _appKey() private pure returns (bytes32) {
        return appKey(app());
    }
}
