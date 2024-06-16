import { ethernal } from "hardhat";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const deploy: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const { deployments, getNamedAccounts } = hre;
    const { deployer } = await getNamedAccounts();
    const { deploy } = deployments;

    let addr = await deploy("OpenIDVerifier", {
        // to: deployer,
        from: deployer,
        args: [],
        log: true,
        // deterministicDeployment: true,
    });

    await hre.ethernal.push({
        name: 'OpenIDVerifier',
        address: addr.address,
    })
    console.log("OpenIDVerifier deployed to:", addr.address);
    console.log("OpenIDVerifier deployed by:", deployer);
};

deploy.tags = ["social_recovery"];
export default deploy;
