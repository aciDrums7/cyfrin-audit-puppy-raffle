Denial of Service attack

### [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack, incrementing gas cost for future entrants

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

**Impact:** The has costs for raffle entrants will greatly increase as more players enter the raffle,discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:** (Proof of Code)

If we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: ~6250668 gas
- 2st 100 players: ~18068760 gas

This is more than 3x more expensive for the second 100 players.

<details></details>
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

3. Alternatively, you could use [Openzeppelin's `EnumberableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).