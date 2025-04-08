// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CelestiaBatchVerifierWrapper.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy wrapper contract
        CelestiaBatchVerifierWrapper wrapper = new CelestiaBatchVerifierWrapper();

        vm.stopBroadcast();

        console.log("Wrapper deployed to:", address(wrapper));
    }
}
