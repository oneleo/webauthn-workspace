// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9.0;

import "@account-abstraction/contracts/samples/IOracle.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV2V3Interface.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract UsdtOracle is IOracle {
    using SafeMath for uint256;
    using SafeCast for int256;
    AggregatorV2V3Interface public immutable usdtAggregator;
    uint8 public immutable decimals;

    constructor(address _usdtAggregatorAddress) {
        usdtAggregator = AggregatorV2V3Interface(_usdtAggregatorAddress);
        decimals = AggregatorV2V3Interface(usdtAggregator).decimals();
    }

    function latestAnswer() public view returns (uint256) {
        return
            usdtAggregator.latestAnswer().toUint256();
    }

    function getTokenValueOfEth(
        uint256 ethOutput
    ) external view override returns (uint256 tokenInput) {
        return
            ethOutput.div(
                AggregatorV2V3Interface(usdtAggregator)
                    .latestAnswer()
                    .toUint256()
            );
    }
}
