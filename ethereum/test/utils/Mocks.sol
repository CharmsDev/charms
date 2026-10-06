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

/// @dev Takes 1% out of every transfer except one into `exempt`. `wrap` exempts the vault, so the
/// contract receives the full amount. `unwrap` sends onward, and the recipient receives 99%.
contract OutboundFeeToken is MockToken {
    address public exempt;

    constructor() MockToken("OutFee", "OFEE", 6) {}

    function setExempt(address who) external {
        exempt = who;
    }

    function _update(address from, address to, uint256 amount) internal override {
        if (from != address(0) && to != address(0) && to != exempt) {
            uint256 fee = amount / 100;
            if (fee != 0) {
                super._update(from, address(0xfee), fee);
                amount -= fee;
            }
        }
        super._update(from, to, amount);
    }
}

/// @dev Charges 1% on top of the amount, except into `exempt`. The sender pays `amount + fee`.
/// `wrap` exempts the vault. This shape is unsupported on `unwrap`: the extra debit comes out of
/// collateral `locked` still counts.
contract ExtraFeeToken is MockToken {
    address public exempt;

    constructor() MockToken("ExtraFee", "XFEE", 6) {}

    function setExempt(address who) external {
        exempt = who;
    }

    function _update(address from, address to, uint256 amount) internal override {
        if (from != address(0) && to != address(0) && to != exempt) {
            uint256 fee = amount / 100;
            if (fee != 0) super._update(from, address(0xfee), fee);
        }
        super._update(from, to, amount);
    }
}

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
        (address owner,) = charms.utxo(ICharmsTypes.UtxoRef(txId, index));
        (address recovered,,) = ECDSA.tryRecover(hash, signature);
        return
            owner == address(this) && recovered == signer ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

interface ICharmsUtxo {
    function utxo(ICharmsTypes.UtxoRef calldata u)
        external
        view
        returns (address owner, bytes memory body);
}

contract RejectEth {
    receive() external payable {
        revert("no eth");
    }
}
