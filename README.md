# la-workshop-2022

Solidity workshop introducing the OpenZeppelin framework for writing contracts, and other libraries

## Where to begin

To create a Solidity project, it is easiest to create a project with a `hardhat.config.js` file saved at the root of the folder, which should at the very least contain this:

```js
module.exports = {
  solidity: '0.8.17'
}
```

Create the `package.json` file at the root of the folder with the `yarn init` command. A Solidity project is often modeled as a standard JavaScript package.

Once the project is initialized, install hardhat with

```sh
yarn add -D hardhat
```

Then, you can create a folder `contracts/` at the root of the directory and begin to put `*.sol` files within the descendent file hierarchy.

Similar to how packages can be imported in JavaScript, you can import Solidity contracts and libraries from the installation from npm, within a Solidity file in your source tree.

There are some useful libraries that can be imported in a Solidity 0.8 project. Ones which are built for an older version of the compiler will have to be inlined in your source tree, and the code copied into the new file with the updated pragma statements.

OpenZeppelin has a strong history of shipping compatible Solidity files for every major Solidity update. The @openzeppelin/contracts repo can be installed to the project with

```sh
yarn add -D @openzeppelin/contracts
```

## OpenZeppelin contracts: brief overview

The list of contracts shipped within this module, and a description of ones you will likely deal with often designing Solidity systems, are as follows:

- @openzeppelin/contracts/finance/PaymentSplitter.sol
- @openzeppelin/contracts/finance/VestingWallet.sol
- @openzeppelin/contracts/token/ERC20/IERC20.sol
  - Interface to ERC20. Wrap an address type in IERC20 like

```js

IERC20 someERC20 = IERC20(someAddress);
require(someERC20.transfer(someRecipient, someAmount), "!transfer");
```

- @openzeppelin/contracts/token/ERC20/utils/TokenTimelock.sol
- @openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol
  - Helper functions that extend the IERC20 type with functions that are compatbile with the entire world of ERC20s which exist, even ones which are not implemented correctly. It is better to use the SafeERC20 methods when possible. Adds functions `safeTransfer(address, uint256)` and `safeTransferFrom(address, address, uint256)` to the IERC20 type when a `using SafeERC20 for IERC20` statement is used in a Solidity contract.

```js

pragma solidity >=0.8.0;

import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ERC20Consumer {
  using SafeERC20 for IERC20;
  address constant usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
  address constant someAddress = 0xfa8C4D926B5E57A9429EC38e23Aa4A93d4d70313;
  function transferSomeERC20() public {
    IERC20 someERC20 = IERC20(someAddress);
    someERC20.safeTransfer(someAddress, uint256(10e18));
  }
}

```

- @openzeppelin/contracts/token/ERC20/ERC20.sol
  - Complete ERC20 implementation, useful to extend to make your own ERC20 contract

```js

pragma solidity >=0.8.0;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract GenericCoin is ERC20 {
  constructor() ERC20("Generic Coin", "GENE") {
    _mint(msg.sender, 1000000e18);
  }
}
```

- @openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol
- @openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20FlashMint.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol
  - Vault implementation. Useful for writing yield farming strategies or otherwise managing a portfolio of wealth from a single address in some fixed strategy (or dynamic). To create a vault, it is only needed to extend ERC4626 and implement the following functions:
    - `function _deposit(address,address,uint256,uint256) internal virtual` 
      - Should handle the logic for depositing some amount of the input token and swapping it to the vault strategy
    - `function _withdraw(address,address,address,uint256,uint256) internal virtual` 
      - Should handle the logic prior to sending back to the input token after burning some amount of vault shares
    - `function totalAssets() public virtual returns (uint256)`
      - Should always return the total amount of value stored in the vault at any given time in terms of the input asset
    - Call the ERC4626(address) constructor in your derived constructor and pass in the address of the input token to the vault, which is managed in the vault code
- @openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20VotesComp.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol
- @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol
- @openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol
  - Base contract that can be extended to support the ERC20Permit API, meaning your ERC20 will expose `function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)` which makes it possible to use offline signatures in lieu of making an explicit `ERC20.approve(address, uint256)` call
- @openzeppelin/contracts/token/ERC20/extensions/draft-IERC20Permit.sol
- @openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol
- @openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol
- @openzeppelin/contracts/token/ERC1155/utils/ERC1155Receiver.sol
- @openzeppelin/contracts/token/ERC1155/presets/ERC1155PresetMinterPauser.sol
- @openzeppelin/contracts/token/ERC1155/extensions/ERC1155URIStorage.sol
- @openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol
- @openzeppelin/contracts/token/ERC1155/extensions/ERC1155Pausable.sol
- @openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol
- @openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol
- @openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol
- @openzeppelin/contracts/token/ERC1155/IERC1155.sol
- @openzeppelin/contracts/token/ERC1155/ERC1155.sol
  - Base contract for ERC1155, which is an NFT that meets the multi token standard, (i.e. you can have more than 1 of a given NFT in a system)
- @openzeppelin/contracts/token/common/ERC2981.sol
  - NFT royalty standard
- @openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol
- @openzeppelin/contracts/token/ERC721/presets/ERC721PresetMinterPauserAutoId.so
- @openzeppelin/contracts/token/ERC721/extensions/ERC721Pausable.sol
- @openzeppelin/contracts/token/ERC721/extensions/draft-ERC721Votes.sol
- @openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol
- @openzeppelin/contracts/token/ERC721/extensions/ERC721Consecutive.sol
- @openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol
- @openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol
- @openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol
- @openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol
- @openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol
- @openzeppelin/contracts/token/ERC721/ERC721.sol
  - Standard NFT implementation, can be extended to create new NFT contracts
- @openzeppelin/contracts/token/ERC721/IERC721.sol
- @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol
- @openzeppelin/contracts/token/ERC777/presets/ERC777PresetFixedSupply.sol
- @openzeppelin/contracts/token/ERC777/IERC777.sol
- @openzeppelin/contracts/token/ERC777/IERC777Sender.sol
- @openzeppelin/contracts/token/ERC777/ERC777.sol
  - Advanced ERC20 standard to support more complex actions upon token receipt
- @openzeppelin/contracts/token/ERC777/IERC777Recipient.sol
- @openzeppelin/contracts/utils/StorageSlot.sol
  - Exposes methods to get a getter/setter for a given storage slot, using storage structs to get a reference to the slot for reading/writing
- @openzeppelin/contracts/utils/escrow/ConditionalEscrow.sol
- @openzeppelin/contracts/utils/escrow/RefundEscrow.sol
- @openzeppelin/contracts/utils/escrow/Escrow.sol
- @openzeppelin/contracts/utils/Arrays.sol
  - Exposes methods on storage arrays for unsafe access which skips the out-of-bounds check. The out-of-bounds check is usually done in compiled Solidity code that accesses storage arrays
- @openzeppelin/contracts/utils/Context.sol
  - Base class used for compatibility with OpenZeppelin gas station network. You will see the method `_msgSender()` used a lot in place of `msg.sender` in OpenZeppelin contracts. It is made available by this contract
- @openzeppelin/contracts/utils/cryptography/ECDSA.sol
  - Helper functions to recover signer addresses from offline signature, expecting a 65 byte `bytes memory` type for the signature and a `bytes32` type for the digest to recover from
- @openzeppelin/contracts/utils/cryptography/draft-EIP712.sol
- @openzeppelin/contracts/utils/cryptography/EIP712.sol
  - Allows you to write your own EIP712 signature schemas. EIP712 is the form of an offline signature possible within MetaMask and other wallets where the user is presented a list of the pieces of data that he is signing, before he clicks sign
- @openzeppelin/contracts/utils/cryptography/MerkleProof.sol
  - Implement Merkle proof verification. Often used in modern airdrop contracts where a merkle tree is generated containing every pair of users and the amount they are being airdropped, as well as a proof for the entry. The root hash of the tree is uploaded to the chain when the contract is constructed, and the entire merkle tree is bundled into the application as a JSON file. The user, when they have an airdrop available, will submit their entry along with the proof and the contract will validate that the submission proves the inclusion of the amount the user is slated to receive against the root hash, transfers the tokens to the user, and marks the proof as spent.
- @openzeppelin/contracts/utils/cryptography/SignatureChecker.sol
- @openzeppelin/contracts/utils/Address.sol
  - Contains functions such as `isContract(address)` to verify that an address is that of an existing contract, `sendValue(address, amount)` which sends ETH to an address with no gas constraints, as opposed to doing `someAddress.transfer(amount)` which does not work when sending ETH to a contract`
- @openzeppelin/contracts/utils/Checkpoints.sol
- @openzeppelin/contracts/utils/math/Math.sol
  - Contains useful functions such as `Math.max(uint256, uint256)` or `Math.min(uint256, uint256)`, `Math.ceilDiv(uint256, uint256)`, `Math.average(uint256, uint256)`, `Math.mulDiv(uint256, uint256, uint256)`, `Math.sqrt(uint256)`, `Math.log2(uint256)`, `Math.log10(uint256)`, `Math.log256(uint256)`
- @openzeppelin/contracts/utils/math/SignedSafeMath.sol
- @openzeppelin/contracts/utils/math/SafeCast.sol
- @openzeppelin/contracts/utils/math/SafeMath.sol
- @openzeppelin/contracts/utils/math/SignedMath.sol
- @openzeppelin/contracts/utils/Create2.sol
  - Helper function to use the `create2` opcode, useful for creating contracts at a known address based on some bytes32 salt
- @openzeppelin/contracts/utils/Timers.sol
- @openzeppelin/contracts/utils/Counters.sol
- @openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol
- @openzeppelin/contracts/utils/structs/EnumerableMap.sol
- @openzeppelin/contracts/utils/structs/BitMaps.sol
- @openzeppelin/contracts/utils/structs/EnumerableSet.sol
- @openzeppelin/contracts/utils/Multicall.sol
- @openzeppelin/contracts/utils/introspection/ERC165Storage.sol
- @openzeppelin/contracts/utils/introspection/ERC165.sol
- @openzeppelin/contracts/utils/introspection/ERC165Checker.sol
- @openzeppelin/contracts/utils/introspection/IERC1820Implementer.sol
- @openzeppelin/contracts/utils/introspection/ERC1820Implementer.sol
- @openzeppelin/contracts/utils/introspection/IERC165.sol
- @openzeppelin/contracts/utils/introspection/IERC1820Registry.sol
- @openzeppelin/contracts/utils/Base64.sol
- @openzeppelin/contracts/utils/Strings.sol
  - Contains functions to convert numeric types to base10 or base16 strings
- @openzeppelin/contracts/metatx/MinimalForwarder.sol
- @openzeppelin/contracts/metatx/ERC2771Context.sol
- @openzeppelin/contracts/governance/IGovernor.sol
- @openzeppelin/contracts/governance/utils/IVotes.sol
- @openzeppelin/contracts/governance/utils/Votes.sol
- @openzeppelin/contracts/governance/extensions/GovernorProposalThreshold.sol
- @openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol
- @openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol
- @openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol
- @openzeppelin/contracts/governance/extensions/GovernorVotesComp.sol
- @openzeppelin/contracts/governance/extensions/IGovernorTimelock.sol
- @openzeppelin/contracts/governance/extensions/GovernorTimelockCompound.sol
- @openzeppelin/contracts/governance/extensions/GovernorPreventLateQuorum.sol
- @openzeppelin/contracts/governance/extensions/GovernorSettings.sol
- @openzeppelin/contracts/governance/extensions/GovernorVotes.sol
- @openzeppelin/contracts/governance/compatibility/GovernorCompatibilityBravo.sol
- @openzeppelin/contracts/governance/compatibility/IGovernorCompatibilityBravo.sol
- @openzeppelin/contracts/governance/TimelockController.sol
- @openzeppelin/contracts/governance/Governor.sol
- @openzeppelin/contracts/interfaces/IERC20.sol
- @openzeppelin/contracts/interfaces/IERC1820Implementer.sol
- @openzeppelin/contracts/interfaces/IERC721Enumerable.sol
- @openzeppelin/contracts/interfaces/IERC3156.sol
- @openzeppelin/contracts/interfaces/IERC2981.sol
- @openzeppelin/contracts/interfaces/IERC1363Receiver.sol
- @openzeppelin/contracts/interfaces/IERC165.sol
- @openzeppelin/contracts/interfaces/IERC1363.sol
- @openzeppelin/contracts/interfaces/IERC2309.sol
- @openzeppelin/contracts/interfaces/README.adoc
- @openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol
- @openzeppelin/contracts/interfaces/IERC1155Receiver.sol
- @openzeppelin/contracts/interfaces/draft-IERC2612.sol
- @openzeppelin/contracts/interfaces/IERC1363Spender.sol
- @openzeppelin/contracts/interfaces/IERC777.sol
- @openzeppelin/contracts/interfaces/IERC721Metadata.sol
- @openzeppelin/contracts/interfaces/IERC1271.sol
- @openzeppelin/contracts/interfaces/IERC721.sol
- @openzeppelin/contracts/interfaces/IERC777Sender.sol
- @openzeppelin/contracts/interfaces/IERC721Receiver.sol
- @openzeppelin/contracts/interfaces/IERC20Metadata.sol
- @openzeppelin/contracts/interfaces/IERC1155MetadataURI.sol
- @openzeppelin/contracts/interfaces/IERC1820Registry.sol
- @openzeppelin/contracts/interfaces/IERC4626.sol
- @openzeppelin/contracts/interfaces/IERC1155.sol
- @openzeppelin/contracts/interfaces/draft-IERC1822.sol
- @openzeppelin/contracts/interfaces/IERC3156FlashLender.sol
- @openzeppelin/contracts/interfaces/IERC777Recipient.sol
- @openzeppelin/contracts/security/ReentrancyGuard.sol
- @openzeppelin/contracts/security/PullPayment.sol
- @openzeppelin/contracts/security/Pausable.sol
- @openzeppelin/contracts/vendor/amb/IAMB.sol
- @openzeppelin/contracts/vendor/compound/ICompoundTimelock.sol
- @openzeppelin/contracts/vendor/compound/LICENSE
- @openzeppelin/contracts/vendor/polygon/IFxMessageProcessor.sol
- @openzeppelin/contracts/vendor/optimism/ICrossDomainMessenger.sol
- @openzeppelin/contracts/vendor/arbitrum/IInbox.sol
- @openzeppelin/contracts/vendor/arbitrum/IBridge.sol
- @openzeppelin/contracts/vendor/arbitrum/IOutbox.sol
- @openzeppelin/contracts/vendor/arbitrum/IArbSys.sol
- @openzeppelin/contracts/vendor/arbitrum/IMessageProvider.sol
- @openzeppelin/contracts/crosschain/amb/CrossChainEnabledAMB.sol
- @openzeppelin/contracts/crosschain/amb/LibAMB.sol
- @openzeppelin/contracts/crosschain/errors.sol
- @openzeppelin/contracts/crosschain/polygon/CrossChainEnabledPolygonChild.sol
- @openzeppelin/contracts/crosschain/optimism/LibOptimism.sol
- @openzeppelin/contracts/crosschain/optimism/CrossChainEnabledOptimism.sol
- @openzeppelin/contracts/crosschain/arbitrum/CrossChainEnabledArbitrumL1.sol
- @openzeppelin/contracts/crosschain/arbitrum/LibArbitrumL2.sol
- @openzeppelin/contracts/crosschain/arbitrum/CrossChainEnabledArbitrumL2.sol
- @openzeppelin/contracts/crosschain/arbitrum/LibArbitrumL1.sol
- @openzeppelin/contracts/crosschain/CrossChainEnabled.sol
- @openzeppelin/contracts/mocks/GovernorTimelockCompoundMock.sol
- @openzeppelin/contracts/mocks/MathMock.sol
- @openzeppelin/contracts/mocks/BadBeacon.sol
- @openzeppelin/contracts/mocks/ERC20CappedMock.sol
- @openzeppelin/contracts/mocks/ERC20PausableMock.sol
- @openzeppelin/contracts/mocks/Base64Mock.sol
- @openzeppelin/contracts/mocks/TimersBlockNumberImpl.sol
- @openzeppelin/contracts/mocks/GovernorTimelockControlMock.sol
- @openzeppelin/contracts/mocks/ERC1155ReceiverMock.sol
- @openzeppelin/contracts/mocks/AccessControlCrossChainMock.sol
- @openzeppelin/contracts/mocks/TimersTimestampImpl.sol
- @openzeppelin/contracts/mocks/PullPaymentMock.sol
- @openzeppelin/contracts/mocks/EnumerableMapMock.sol
- @openzeppelin/contracts/mocks/ContextMock.sol
- @openzeppelin/contracts/mocks/ERC165CheckerMock.sol
- @openzeppelin/contracts/mocks/compound
- @openzeppelin/contracts/mocks/compound/CompTimelock.sol
- @openzeppelin/contracts/mocks/SignatureCheckerMock.sol
- @openzeppelin/contracts/mocks/DummyImplementation.sol
- @openzeppelin/contracts/mocks/AccessControlEnumerableMock.sol
- @openzeppelin/contracts/mocks/ERC721VotesMock.sol
- @openzeppelin/contracts/mocks/ERC20WrapperMock.sol
- @openzeppelin/contracts/mocks/ERC1155PausableMock.sol
- @openzeppelin/contracts/mocks/ERC20BurnableMock.sol
- @openzeppelin/contracts/mocks/GovernorVoteMock.sol
- @openzeppelin/contracts/mocks/ERC20FlashMintMock.sol
- @openzeppelin/contracts/mocks/ERC20VotesMock.sol
- @openzeppelin/contracts/mocks/SignedSafeMathMock.sol
- @openzeppelin/contracts/mocks/MulticallTokenMock.sol
- @openzeppelin/contracts/mocks/ERC20PermitMock.sol
- @openzeppelin/contracts/mocks/MultipleInheritanceInitializableMocks.sol
- @openzeppelin/contracts/mocks/ERC165Mock.sol
- @openzeppelin/contracts/mocks/ERC1820ImplementerMock.sol
- @openzeppelin/contracts/mocks/SafeERC20Helper.sol
- @openzeppelin/contracts/mocks/ERC1271WalletMock.sol
- @openzeppelin/contracts/mocks/GovernorPreventLateQuorumMock.sol
- @openzeppelin/contracts/mocks/EIP712External.sol
- @openzeppelin/contracts/mocks/MerkleProofWrapper.sol
- @openzeppelin/contracts/mocks/ClonesMock.sol
- @openzeppelin/contracts/mocks/ERC1155Mock.sol
- @openzeppelin/contracts/mocks/wizard/MyGovernor2.sol
- @openzeppelin/contracts/mocks/wizard/MyGovernor3.sol
- @openzeppelin/contracts/mocks/wizard/MyGovernor1.sol
- @openzeppelin/contracts/mocks/ReentrancyAttack.sol
- @openzeppelin/contracts/mocks/OwnableMock.sol
- @openzeppelin/contracts/mocks/CallReceiverMock.sol
- @openzeppelin/contracts/mocks/ERC721ReceiverMock.sol
- @openzeppelin/contracts/mocks/StorageSlotMock.sol
- @openzeppelin/contracts/mocks/CheckpointsMock.sol
- @openzeppelin/contracts/mocks/SignedMathMock.sol
- @openzeppelin/contracts/mocks/SingleInheritanceInitializableMocks.sol
- @openzeppelin/contracts/mocks/StringsMock.sol
- @openzeppelin/contracts/mocks/ClashingImplementation.sol
- @openzeppelin/contracts/mocks/VotesMock.sol
- @openzeppelin/contracts/mocks/GovernorWithParamsMock.sol
- @openzeppelin/contracts/mocks/EnumerableSetMock.sol
- @openzeppelin/contracts/mocks/ArraysMock.sol
- @openzeppelin/contracts/mocks/ERC20DecimalsMock.sol
- @openzeppelin/contracts/mocks/ERC721RoyaltyMock.sol
- @openzeppelin/contracts/mocks/ECDSAMock.sol
- @openzeppelin/contracts/mocks/ERC721URIStorageMock.sol
- @openzeppelin/contracts/mocks/GovernorMock.sol
- @openzeppelin/contracts/mocks/ERC1155URIStorageMock.sol
- @openzeppelin/contracts/mocks/ERC1155SupplyMock.sol
- @openzeppelin/contracts/mocks/GovernorCompMock.sol
- @openzeppelin/contracts/mocks/ERC165/ERC165InterfacesSupported.sol
- @openzeppelin/contracts/mocks/ERC165/ERC165NotSupported.sol
- @openzeppelin/contracts/mocks/ERC165/ERC165ReturnBomb.sol
- @openzeppelin/contracts/mocks/ERC165/ERC165MissingData.sol
- @openzeppelin/contracts/mocks/ERC165/ERC165MaliciousData.sol
- @openzeppelin/contracts/mocks/ERC721Mock.sol
- @openzeppelin/contracts/mocks/PausableMock.sol
- @openzeppelin/contracts/mocks/ERC777Mock.sol
- @openzeppelin/contracts/mocks/DoubleEndedQueueMock.sol
- @openzeppelin/contracts/mocks/ERC721BurnableMock.sol
- @openzeppelin/contracts/mocks/ERC721PausableMock.sol
- @openzeppelin/contracts/mocks/Create2Impl.sol
- @openzeppelin/contracts/mocks/ReentrancyMock.sol
- @openzeppelin/contracts/mocks/SafeMathMock.sol
- @openzeppelin/contracts/mocks/MulticallTest.sol
- @openzeppelin/contracts/mocks/crosschain/receivers.sol
- @openzeppelin/contracts/mocks/crosschain/bridges.sol
- @openzeppelin/contracts/mocks/UUPS/UUPSLegacy.sol
- @openzeppelin/contracts/mocks/UUPS/UUPSUpgradeableMock.sol
- @openzeppelin/contracts/mocks/ConditionalEscrowMock.sol
- @openzeppelin/contracts/mocks/AccessControlMock.sol
- @openzeppelin/contracts/mocks/ERC20VotesCompMock.sol
- @openzeppelin/contracts/mocks/ERC3156FlashBorrowerMock.sol
- @openzeppelin/contracts/mocks/ERC2771ContextMock.sol
- @openzeppelin/contracts/mocks/Ownable2StepMock.sol
- @openzeppelin/contracts/mocks/EtherReceiverMock.sol
- @openzeppelin/contracts/mocks/ERC777SenderRecipientMock.sol
- @openzeppelin/contracts/mocks/ERC1155BurnableMock.sol
- @openzeppelin/contracts/mocks/GovernorCompatibilityBravoMock.sol
- @openzeppelin/contracts/mocks/ERC20Mock.sol
- @openzeppelin/contracts/mocks/RegressionImplementation.sol
- @openzeppelin/contracts/mocks/ERC165StorageMock.sol
- @openzeppelin/contracts/mocks/AddressImpl.sol
- @openzeppelin/contracts/mocks/ERC721ConsecutiveMock.sol
- @openzeppelin/contracts/mocks/ERC4626Mock.sol
- @openzeppelin/contracts/mocks/InitializableMock.sol
- @openzeppelin/contracts/mocks/CountersImpl.sol
- @openzeppelin/contracts/mocks/ERC721EnumerableMock.sol
- @openzeppelin/contracts/mocks/SafeCastMock.sol
- @openzeppelin/contracts/mocks/ERC20SnapshotMock.sol
- @openzeppelin/contracts/mocks/BitmapMock.sol
- @openzeppelin/contracts/access/IAccessControl.sol
- @openzeppelin/contracts/access/AccessControl.sol
- @openzeppelin/contracts/access/AccessControlEnumerable.sol
- @openzeppelin/contracts/access/Ownable2Step.sol
- @openzeppelin/contracts/access/Ownable.sol
  - Contains `tranferOwnership(address)` and `onlyOwner` modifiers. Tracks a single `owner` public variable. Useful for an easy way to add administrative functionality to a contract. The owner address can be a governance contract, which is a very common pattern
- @openzeppelin/contracts/access/AccessControlCrossChain.sol
- @openzeppelin/contracts/access/IAccessControlEnumerable.sol
- @openzeppelin/contracts/proxy/Clones.sol
  - Useful functions for creating contracts or determining the addresses of contracts which are short and cheap-to-deploy bytecode snippets that simply delegate to an address which contains the full bytecode. Useful to instantiate contracts extremely cheaper, for contracts which ultimately would have the same bytecode and need to be created often
- @openzeppelin/contracts/proxy/utils/Initializable.sol
  - Useful for OpenZeppelin upgradeable contracts, creates an `initializer` function which can be added to a `function initialize() public` signature so there can be constructor logic in contracts where the constructor is not ever actually run, such as a clone or proxy
- @openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol
- @openzeppelin/contracts/proxy/beacon/BeaconProxy.sol
- @openzeppelin/contracts/proxy/beacon/IBeacon.sol
- @openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol
- @openzeppelin/contracts/proxy/Proxy.sol
- @openzeppelin/contracts/proxy/ERC1967
- @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
- @openzeppelin/contracts/proxy/ERC1967/ERC1967Upgrade.sol
- @openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol
  - Standard contract in OpenZeppelin to manage setting the implementation address or upgrading a contract proxy to use a different implementation. The ProxyAdmin has an owner address which is authorized to upgrade a set of proxies
- @openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
  - Standard contract which is the frontend contract for a proxy. Exposes the bare minimal functionality to change the implementation address for the proxy, or otherwise to delegate any other transaction to the implementation contract address which is set at the time the transaction is executed

## Author

flex
