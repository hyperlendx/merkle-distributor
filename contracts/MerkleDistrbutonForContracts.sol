// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.17;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

error AlreadyClaimed();
error InvalidProof();
error EndTimeInPast();
error ClaimWindowFinished();
error NoWithdrawDuringClaim();

interface IMerkleDistributor {
    function token() external view returns (address);
    function merkleRoot() external view returns (bytes32);
    function isClaimed(uint256 index) external view returns (bool);
    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof, address recipient) external;
}

/*
MerkleDistributorWithDeadline with additional features:
    - owner can update recipient
    - only account or recipient can claim (to prevent grifters from claiming tokens to contracts)
*/
contract MerkleDistributorForContracts is IMerkleDistributor, Ownable {
    using SafeERC20 for IERC20;

    address public immutable override token;
    bytes32 public immutable override merkleRoot;
    uint256 public immutable endTime;

    // This is a packed array of booleans.
    mapping(uint256 => uint256) private claimedBitMap;
    mapping(address => address) public recipients;

    event RecipientSet(address account, address recipient);
    event ClaimedTo(uint256 index, address account, uint256 amount, address recipient);

    constructor(address token_, bytes32 merkleRoot_, uint256 endTime_) {
        if (endTime_ <= block.timestamp) revert EndTimeInPast();
        endTime = endTime_;
        token = token_;
        merkleRoot = merkleRoot_;
    }

    function isClaimed(uint256 index) public view override returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);
    }

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof, address recipient)
        public
        virtual
        override
    {
        if (block.timestamp > endTime) revert ClaimWindowFinished();
        if (isClaimed(index)) revert AlreadyClaimed();
        require(msg.sender == account || msg.sender == recipients[account], 'msg.sender not authorized');
        
        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        if (!MerkleProof.verify(merkleProof, merkleRoot, node)) revert InvalidProof();

        // Mark it claimed and send the token.
        _setClaimed(index);

        // Send tokens to recipient instead of account
        if (recipients[account] != address(0)){
            require(recipient == recipients[account], 'invalid recipient'); //double check that recipient set by owner is the one claimer wants to use
            IERC20(token).safeTransfer(recipients[account], amount);
        } else {
            IERC20(token).safeTransfer(account, amount);
        }
        
        emit ClaimedTo(index, account, amount, recipient);
    }

    function setRecipients(address[] calldata _accounts, address[] calldata _recipients) external onlyOwner {
        require(_accounts.length == _recipients.length, 'invalid lengths');

        for (uint256 i = 0; i < _accounts.length; i++){
            require(_recipients[i] != address(0), 'invalid recipient');
            recipients[_accounts[i]] = _recipients[i];
            emit RecipientSet(_accounts[i], _recipients[i]);
        }
    }

    function withdraw() external onlyOwner {
        if (block.timestamp < endTime) revert NoWithdrawDuringClaim();
        IERC20(token).safeTransfer(msg.sender, IERC20(token).balanceOf(address(this)));
    }
}
