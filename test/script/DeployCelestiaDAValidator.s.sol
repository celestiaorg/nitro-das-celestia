// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/CelestiaDAProofValidator.sol";

contract DeployCelestiaDAValidator is Script {
    function run() external {
        address blobstream = vm.envAddress("BLOBSTREAM_ADDR");
        vm.startBroadcast();

        CelestiaDAProofValidator validator = new CelestiaDAProofValidator(blobstream);

        vm.stopBroadcast();
        console.log("CelestiaDAProofValidator deployed to:", address(validator));
    }
}
