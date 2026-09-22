const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("=================================================");
  console.log("DEPLOYING FILE METADATA REGISTRY SMART CONTRACT");
  console.log("=================================================");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer Account Address:", deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Deployer Account Balance:", hre.ethers.formatEther(balance), "ETH");

  const FileMetadataRegistry = await hre.ethers.getContractFactory("FileMetadataRegistry");
  const registry = await FileMetadataRegistry.deploy();

  await registry.waitForDeployment();

  const contractAddress = await registry.getAddress();
  console.log("-------------------------------------------------");
  console.log("SUCCESS: FileMetadataRegistry deployed!");
  console.log("Contract Address:", contractAddress);
  console.log("=================================================");

  // Save deployment metadata to deployment-info.json
  const deploymentInfo = {
    network: hre.network.name,
    chainId: hre.network.config.chainId || 31337,
    contractAddress: contractAddress,
    deployerAddress: deployer.address,
    deployedAt: new Date().toISOString()
  };

  const outputPath = path.join(__dirname, "..", "deployment-info.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`Saved deployment info to: ${outputPath}`);
}

main().catch((error) => {
  console.error("Deployment Error:", error);
  process.exitCode = 1;
});
