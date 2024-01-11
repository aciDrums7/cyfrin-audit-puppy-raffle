// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
// @reported use of floating pragma is bad!
// @reported also... why are you using 0.7.6???

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Base64} from "lib/base64/base64.sol";

/// @title PuppyRaffle
/// @author PuppyLoveDAO
/// @notice This project is to enter a raffle to win a cute dog NFT. The protocol should do the following:
/// 1. Call the `enterRaffle` function with the following parameters:
///    1. `address[] participants`: A list of addresses that enter. You can use this to enter yourself multiple times, or yourself and a group of your friends.
/// 2. Duplicate addresses are not allowed
/// 3. Users are allowed to get a refund of their ticket & `value` if they call the `refund` function
/// 4. Every X seconds, the raffle will be able to draw a winner and be minted a random puppy
/// 5. The owner of the protocol will set a feeAddress to take a cut of the `value`, and the rest of the funds will be sent to the winner of the puppy.
contract PuppyRaffle is ERC721, Ownable {
    using Address for address payable;

    uint256 public immutable entranceFee;

    address[] public players;

    // @reported should be immutable!
    uint256 public raffleDuration;

    uint256 public raffleStartTime;
    address public previousWinner;

    // We do some storage packing to save gas
    address public feeAddress;
    uint64 public totalFees = 0;

    // mappings to keep track of token traits
    mapping(uint256 => uint256) public tokenIdToRarity;
    mapping(uint256 => string) public rarityToUri;
    mapping(uint256 => string) public rarityToName;

    // Stats for the common puppy (pug)
    // @audit-gas should be constant!
    string private commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";

    uint256 public constant COMMON_RARITY = 70;
    string private constant COMMON = "common";

    // Stats for the rare puppy (st. bernard)
    // @audit-gas should be constant!
    string private rareImageUri = "ipfs://QmUPjADFGEKmfohdTaNcWhp7VGk26h5jXDA7v3VtTnTLcW";

    uint256 public constant RARE_RARITY = 25;
    string private constant RARE = "rare";

    // Stats for the legendary puppy (shiba inu)
    // @audit-gas should be constant!
    string private legendaryImageUri = "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";

    uint256 public constant LEGENDARY_RARITY = 5;
    string private constant LEGENDARY = "legendary";

    // Events
    event RaffleEnter(address[] newPlayers);
    event RaffleRefunded(address player);
    event FeeAddressChanged(address newFeeAddress);

    /// @param _entranceFee the cost in wei to enter the raffle
    /// @param _feeAddress the address to send the fees to
    /// @param _raffleDuration the duration in seconds of the raffle
    constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
        entranceFee = _entranceFee;
        // @audit-info check for zero address
        //e input validation
        feeAddress = _feeAddress;
        raffleDuration = _raffleDuration;
        raffleStartTime = block.timestamp;

        // @audit-gas should be constant!
        rarityToUri[COMMON_RARITY] = commonImageUri;
        rarityToUri[RARE_RARITY] = rareImageUri;
        rarityToUri[LEGENDARY_RARITY] = legendaryImageUri;

        rarityToName[COMMON_RARITY] = COMMON;
        rarityToName[RARE_RARITY] = RARE;
        rarityToName[LEGENDARY_RARITY] = LEGENDARY;
    }

    /// @notice this is how players enter the raffle
    /// @notice they have to pay the entrance fee * the number of players
    /// @notice duplicate entrants are not allowed
    /// @param newPlayers the list of players to enter the raffle
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        // @audit no check for address(0)
        for (uint256 i = 0; i < newPlayers.length; i++) {
            // @audit / followup if it's an empty array, we still emit an event?
            players.push(newPlayers[i]);
        }

        // Check for duplicates
        // @audit Dos
        // @audit-gas uint256 playerLength = players.length;
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
        //q if it's an empty array, we still emit an event?
        emit RaffleEnter(newPlayers);
    }

    /// @param playerIndex the index of the player to refund. You can find it externally by calling `getActivePlayerIndex`
    /// @dev This function will allow there to be blank spots in the array
    function refund(uint256 playerIndex) public {
        // @audit MEV
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        // @audit reentrancy
        payable(msg.sender).sendValue(entranceFee);

        players[playerIndex] = address(0);
        // @audit-low
        // If an event can be manipulated
        // An event is missing
        // An event is wrong
        emit RaffleRefunded(playerAddress);
    }

    /// @notice a way to get the index in the array
    /// @param player the address of a player in the raffle
    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        // @audit if the player is at index 0 it'll return 0 and a player might think they are not active!
        return 0;
    }

    /// @notice this function will select a winner and mint a puppy
    /// @notice there must be at least 4 players, and the duration has occurred
    /// @notice the previous winner is stored in the previousWinner variable
    /// @dev we use a hash of on-chain data to generate the random numbers
    /// @dev we reset the active players array after the winner is selected
    /// @dev we send 80% of the funds to the winner, the other 20% goes to the feeAddress
    function selectWinner() external {
        // @audit-info recommend to follow CEI
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");

        // @audit randomness
        // fixes: Chainlink VRF, Commit Reveal Scheme
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];

        // @audit-info why not just do address(this).balance?
        uint256 totalAmountCollected = players.length * entranceFee;

        // @audit-info magic numbers
        // uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
        // uint256 public constant FEE_PERCENTAGE = 20;
        // uint256 public constant POOL_PRECISION = 100;
        // exceptions 0, 1
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
        //1 this is the total fees the owner should be able to collect
        // @audit overflow
        // Fixes: Newer version of solidity, bigger uints
        // @audit unsafe cast of uint256 to uint64
        // 18.446744073709551615
        // 20.000000000000000000 uint256
        // 1.553255926290448384 uint64
        totalFees = totalFees + uint64(fee);

        //e when we mint a new puppy NFT, we use the totalSupply as the tokenId
        uint256 tokenId = totalSupply();

        // We use a different RNG calculate from the winnerIndex to determine rarity
        // @audit randomness

        // @audit people can revert the TX till they win
        uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;
        if (rarity <= COMMON_RARITY) {
            tokenIdToRarity[tokenId] = COMMON_RARITY;
        } else if (rarity <= COMMON_RARITY + RARE_RARITY) {
            tokenIdToRarity[tokenId] = RARE_RARITY;
        } else {
            tokenIdToRarity[tokenId] = LEGENDARY_RARITY;
        }

        delete players; //e resetting the players array
        raffleStartTime = block.timestamp; //e resetting the raffle start time
        previousWinner = winner; //e vanity, doesn't matter much

        // @audit the winner wouldn't get the money if their fallback was messed up!
        (bool success,) = winner.call{value: prizePool}("");
        require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
    }

    /// @notice this function will withdraw the fees to the feeAddress
    function withdrawFees() external {
        //e this condition is true when selectWinner() has been called successfully
        // @audit it is difficult to withdraw fees if there are players (MEV)
        // @audit mishandling ETH, selfdestruct possible
        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        // slither-disable-next-line arbitrary-send-eth
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }

    /// @notice only the owner of the contract can change the feeAddress
    /// @param newFeeAddress the new address to send fees to
    function changeFeeAddress(address newFeeAddress) external onlyOwner {
        feeAddress = newFeeAddress;
        // @audit are we missing events?
        emit FeeAddressChanged(newFeeAddress);
    }

    /// @notice this function will return true if the msg.sender is an active player
    // @audit this isn't used anywhere?
    // IMPACT: None
    // LIKELIHOOD: None
    // ... but it's a waste of gas I/G
    function _isActivePlayer() internal view returns (bool) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == msg.sender) {
                return true;
            }
        }
        return false;
    }

    /// @notice this could be a constant variable
    function _baseURI() internal pure returns (string memory) {
        return "data:application/json;base64,";
    }

    /// @notice this function will return the URI for the token
    /// @param tokenId the Id of the NFT
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "PuppyRaffle: URI query for nonexistent token");

        uint256 rarity = tokenIdToRarity[tokenId];
        string memory imageURI = rarityToUri[rarity];
        string memory rareName = rarityToName[rarity];

        return string(
            abi.encodePacked(
                _baseURI(),
                Base64.encode(
                    bytes(
                        abi.encodePacked(
                            '{"name":"',
                            name(),
                            '", "description":"An adorable puppy!", ',
                            '"attributes": [{"trait_type": "rarity", "value": ',
                            rareName,
                            '}], "image":"',
                            imageURI,
                            '"}'
                        )
                    )
                )
            )
        );
    }
}
