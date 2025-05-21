// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const MainModule = buildModule("MainModule", (m) => {
  const contract = m.contract("Algo2ProxyReencryption", [], {});

  return { contract };
});

export default MainModule;
