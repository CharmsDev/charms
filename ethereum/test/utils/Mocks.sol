// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ICharmsTypes} from "../../src/interfaces/ICharms.sol";
import {ISP1Verifier} from "../../src/interfaces/ISP1Verifier.sol";

contract MockVerifier is ISP1Verifier {
    bool public reject;

    function setReject(bool value) external {
        reject = value;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external view {
        require(!reject, "proof rejected");
    }
}

contract MockToken is ERC20 {
    uint8 private immutable _decimals;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_) {
        _decimals = decimals_;
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Keeps 1% of every transfer, so the receiver gets less than `amount`.
contract FeeToken is MockToken {
    constructor() MockToken("Fee", "FEE", 6) {}

    function _update(address from, address to, uint256 amount) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = amount / 100;
            super._update(from, address(0xfee), fee);
            amount -= fee;
        }
        super._update(from, to, amount);
    }
}

/// @dev An ERC-20 whose `decimals` the test can change after the first wrap.
contract MutableDecimalsToken is MockToken {
    uint8 public dec;

    constructor() MockToken("Mutable", "MUT", 18) {
        dec = 18;
    }

    function setDecimals(uint8 value) external {
        dec = value;
    }

    function decimals() public view override returns (uint8) {
        return dec;
    }
}

/// @dev Implements the ERC-20 calls Charms uses and nothing else, so it has no `decimals`,
/// `name`, or `symbol`.
contract BareToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev An ERC-1271 smart wallet whose signer is one EOA.
contract Wallet1271 {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        (address recovered,,) = ECDSA.tryRecover(hash, signature);
        return recovered == signer ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// @dev Signs a spend only while it still owns the UTXO it is asked about, as a policy wallet
/// might.
contract HoldingWallet1271 {
    address public immutable signer;
    ICharmsUtxo public immutable charms;
    bytes32 public txId;
    uint32 public index;

    constructor(address signer_, ICharmsUtxo charms_) {
        signer = signer_;
        charms = charms_;
    }

    function watch(bytes32 txId_, uint32 index_) external {
        (txId, index) = (txId_, index_);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        (, address owner,,) = charms.utxo(ICharmsTypes.UtxoRef(txId, index));
        (address recovered,,) = ECDSA.tryRecover(hash, signature);
        return
            owner == address(this) && recovered == signer ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

interface ICharmsUtxo {
    function utxo(ICharmsTypes.UtxoRef calldata u)
        external
        view
        returns (uint8 kind, address owner, uint64 amount, bytes memory body);
}

contract RejectEth {
    receive() external payable {
        revert("no eth");
    }
}
