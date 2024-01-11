## [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential Denial of Service (DoS) attack, incrementing gas cost for future entrants

<!-- IMPACT: MEDIUM -->
<!-- LIKELIHOOD: MEDIUM -->

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make. 

```javascript
 // @audit DoS attack
@>      for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```
<!-- this will cause a problem even with front running, we'll talk of it later -->

**Impact:** The costs for raffle entrants will greatly increase as more players enter the raffle, discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:** (Proof of Code)

If we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: ~6.250.668 gas
- 2st 100 players: ~18.068.760 gas

This is more than 3x more expensive for the second 100 players.

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
function test_EnterRaffleDenialOfService() public {
        vm.txGasPrice(1);
        // Let's enter the first 100 players
        uint256 numPlayers = 100;
        address[] memory playersFirst = new address[](numPlayers);
        for (uint256 i; i < numPlayers; ++i) {
            playersFirst[i] = address(i);
        }
        uint256 gasStartFirst = gasleft();
        puppyRaffle.enterRaffle{value: puppyRaffle.entranceFee() * numPlayers}(playersFirst);
        uint256 gasEndFirst = gasleft();

        uint256 gasUsedFirst = (gasStartFirst - gasEndFirst) * tx.gasprice;
        console.log("Gas cost of the first 100 players: ", gasUsedFirst);

        // now for the 2nd 100 players
        address[] memory playersSecond = new address[](numPlayers);
        for (uint256 i; i < numPlayers; ++i) {
            playersSecond[i] = address(i + numPlayers); // 0, 1, 2 -> 100, 101, 102
        }
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: puppyRaffle.entranceFee() * numPlayers}(playersSecond);
        uint256 gasEndSecond = gasleft();

        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;
        console.log("Gas cost of the second 100 players: ", gasUsedSecond);

        assert(gasUsedFirst < gasEndSecond);
    }
```
</details><br>

**Recommended Mitigation:** There are a few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of wether a user has already entered.

```diff
+   uint256 public raffleID = 1;
+   mapping(address => uint256) public playerToRaffleID;
.
.
.
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
+       // check for duplicates only from the new players and before adding them to the raffle
+       for(uint256 i; i < newPlayers.length; i++) {
+           require(playerToRaffleID[newPlayers[i]] != raffleID, "PuppyRaffle: Duplicate player");
+       }

        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           playerToRaffleID[newPlayers[i]] = raffleID; 
        }
-       for (uint256 i = 0; i < players.length - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
-               require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-           }
-       }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
        // existing code
+       raffleID++;
    }
```

1. Alternatively, you could use [Openzeppelin's `EnumberableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).



## [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](../src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```



## [I-2]: Using an outdated version of Solidity is not recommended.

solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation**
Deploy with any of the following Solidity versions:

`0.8.18`
The recommendations take into account:
Risks related to recent releases
Risks of complex code generation changes
Risks of new language features
Risks of known bugs
Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information. 



## [I-3]: Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 69](../src/PuppyRaffle.sol#L69)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 193](../src/PuppyRaffle.sol#L193)

	```solidity
	        previousWinner = winner; //e vanity, doesn't matter much
	```

- Found in src/PuppyRaffle.sol [Line: 217](../src/PuppyRaffle.sol#L217)

	```solidity
	        feeAddress = newFeeAddress;
	``



# Gas

## [G-1] Unchanged state variables should be declared constant or immutable.

Reading from storage is muhc more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`