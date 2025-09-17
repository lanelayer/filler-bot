const { ethers } = require("hardhat");

async function main() {
    console.log("🚀 Deploying IntentSystemSimulator...");

    // Get the contract factory
    const IntentSystemSimulator = await ethers.getContractFactory("IntentSystemSimulator");

    // Deploy the contract
    const simulator = await IntentSystemSimulator.deploy();

    // Wait for deployment to complete
    await simulator.waitForDeployment();

    const address = await simulator.getAddress();
    console.log("✅ IntentSystemSimulator deployed to:", address);

    // Test some basic functionality
    console.log("\n🧪 Testing basic functionality...");

    // Test blob storage
    const testData = ethers.toUtf8Bytes("test blob data");
    const expiryTime = Math.floor(Date.now() / 1000) + 86400; // 1 day from now

    console.log("📦 Storing test blob...");
    const storeTx = await simulator.storeBlob(testData, expiryTime, { value: ethers.parseEther("0.001") });
    await storeTx.wait();
    console.log("✅ Blob stored successfully");

    // Test blob storage check
    const blobHash = ethers.keccak256(testData);
    const isStored = await simulator.blobStored(blobHash);
    console.log("🔍 Blob stored check:", isStored);

    // Test intent creation
    console.log("📝 Creating test intent...");
    const intentData = ethers.toUtf8Bytes("test intent data");
    const nonce = 1;
    const intentTx = await simulator.intent(intentData, nonce, { value: ethers.parseEther("0.1") });
    const intentReceipt = await intentTx.wait();

    // Extract intent ID from event
    const intentCreatedEvent = intentReceipt.logs.find(log => {
        try {
            const parsed = simulator.interface.parseLog(log);
            return parsed.name === "IntentCreated";
        } catch (e) {
            return false;
        }
    });

    if (intentCreatedEvent) {
        const parsed = simulator.interface.parseLog(intentCreatedEvent);
        const intentId = parsed.args.intentId;
        console.log("✅ Intent created with ID:", intentId);

        // Test query functions
        const isSolved = await simulator.isIntentSolved(intentId);
        const locker = await simulator.intentLocker(intentId);
        const value = await simulator.valueStoredInIntent(intentId);

        console.log("🔍 Intent solved:", isSolved);
        console.log("🔍 Intent locker:", locker);
        console.log("🔍 Intent value:", ethers.formatEther(value), "ETH");
    }

    console.log("\n🎉 Simulator contract is ready for testing!");
    console.log("📋 Contract address:", address);
    console.log("📋 ABI available for integration with filler bot");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("❌ Deployment failed:", error);
        process.exit(1);
    });



