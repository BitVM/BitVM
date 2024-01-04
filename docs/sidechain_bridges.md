# Sidechain Bridge 

Trust-minimized two-way peg mechanism.

Write-up is WIP. 

### Background on Bitcoin bridges and cross-chain interoperability in general: 

- [Bitcoin Bridges: Cure or Curse?](https://alexei.tech/files/PizzaDayPrague%20-%20Bitcoin%20Bridges_%20Cure%20or%20Curse.pdf)
- [SoK: Communication Across Distributed Ledgers](https://eprint.iacr.org/2019/1128.pdf)

### Outline: Optimistic, trust-minimized, BTC bridge with BitVM

The main idea behind a BitVM BTC bridge is to create way for Bitcoin full nodes to operate a sidechain bridge program, inlcuding a sidechain light client, using only Bitcoin script. 
While it is known to be impossible to create a such program as an on-chain Bitcoin contract, we make use of BitVM's fraud-proof mechanism to optimistically execute the sidechain light client (and the rest of the bridge program) off-chain, using on-chain transactions only to perform challenges-response games that allow honest actors to prevent dishonest actions by offline or malicious participants. The sidechain implements the equivalent bridge program and Bitcoin light client either as a smart contract. (Note: We need to assume sufficient functionality is available. Alternatively, the sidechain could also implement the bridge program via a BitVM-like mechanism.)

To transfer BTC from Bitcoin to a sidechain, a "Depositor" sends BTC to a multisig controlled by a committee of N members (one Prover="Operator" and N-1 Verifiers="Watchtowers") that commits to the bridge program as part of a BitVM setup. And as long as one of these  participants is honest, the deposits remain secure because malicious committee members will be challenged and their access to BTC deposits removed. Whenever a Depositor requests to redeem wrapped xBTC for BTC the currently active Operator verifies the state of the sidechain off-chain and, if everything is correct, sends BTC to the user from her own balance, i.e., fronts the BTC payment to the user. The Operator then requests a reimbursement of the redeemed BTC amount from the deposit multisig. Watchtowers observe this process and verify correctness. Once the Operator requests a reimbursement, Watchtowers can issue an on-chain challenge during a pre-defined challenge period if their off-chain program execution yields a different result, e.g. the Operator sent the wrong BTC amount or paid to a wrong address. If the Operator does not make a BTC payment within a pre-defined timeout period, Watchtowers challenge inactivity. In both cases, Watchtowers trigger an on-chain challenge-response protocol via BitVM. This process requires multiple on-chain Bitcoin transactions in the worst case and results in the Operator being removed from the committee and losing access to the BTC deposited into the bridge. One of the Watchtowers is then selected as Operator and resumes operation of the bridge. 
To ensure Watchtowers have sufficient incentive to perform challenges (and to cover eventual on-chain Bitcoin transaction fees) the Operator is collateralized on Bitcoin. Similarly, to dis-incentivize false challenges, Watchtowers must also deposit collateral.  

