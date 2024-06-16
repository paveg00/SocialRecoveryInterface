import { ethernal } from "hardhat";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const deploy: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const { deployments, getNamedAccounts } = hre;
    const { deployer } = await getNamedAccounts();
    const { deploy } = deployments;

    let addr = await deploy("RecoveryModule", {
        // to: deployer,
        from: deployer,
        args: [],
        log: true,
        // deterministicDeployment: true,
    });

    await hre.ethernal.push({
        name: 'RecoveryModule',
        address: addr.address,
    })
    console.log("RecoveryModule deployed to:", addr.address);
    console.log("RecoveryModule deployed by:", deployer);
};

deploy.tags = ["social_recovery"];
export default deploy;
