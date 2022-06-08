use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::bail;
use cid::Cid;
use fil_actor_account::State as AccountState;
use fil_actor_cron::State as CronState;
use fil_actor_init::State as InitState;
use fil_actor_market::State as MarketState;
use fil_actor_miner::State as MinerState;
use fil_actor_multisig::State as MultisigState;
use fil_actor_paych::State as PaychState;
use fil_actor_power::State as PowerState;
use fil_actor_reward::State as RewardState;
use fil_actor_verifreg::State as VerifregState;

use fil_actors_runtime::runtime::Policy;
use fil_actors_runtime::Map;
use fil_actors_runtime::MessageAccumulator;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::CborStore;
use fvm_shared::actor::builtin::Manifest;
use fvm_shared::actor::builtin::Type;
use fvm_shared::address::Address;
use fvm_shared::address::Protocol;
use fvm_shared::bigint::BigInt;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use num_traits::Zero;

use anyhow::anyhow;
use fvm_ipld_encoding::tuple::*;
use fvm_shared::bigint::bigint_ser;

use fil_actor_account::testing as account;
use fil_actor_cron::testing as cron;
use fil_actor_init::testing as init;
use fil_actor_market::testing as market;
use fil_actor_miner::testing as miner;
use fil_actor_multisig::testing as multisig;
use fil_actor_paych::testing as paych;
use fil_actor_power::testing as power;
use fil_actor_reward::testing as reward;
use fil_actor_verifreg::testing as verifreg;

pub struct Tree<'a, BS>
where
    BS: Blockstore,
{
    map: Map<'a, BS, Actor>,
    pub store: &'a BS,
}

impl<'a, BS: Blockstore> Tree<'a, BS> {
    pub fn for_each<F>(&self, mut f: F) -> anyhow::Result<()>
    where
        F: FnMut(&Address, &Actor) -> anyhow::Result<()>,
    {
        self.map
            .for_each(|key, val| {
                let address = Address::from_bytes(key)?;
                f(&address, val)
            })
            .map_err(|e| anyhow!("Failed iterating map: {}", e))
    }
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone, PartialEq, Debug)]
pub struct Actor {
    pub code: Cid,
    pub head: Cid,
    pub call_seq_num: u64,
    #[serde(with = "bigint_ser")]
    pub balance: TokenAmount,
}

macro_rules! get_state {
    ($tree:ident, $actor:ident, $state:ty) => {
        $tree
            .store
            .get_cbor::<$state>(&$actor.head)?
            .ok_or_else(|| anyhow!("{} is empty", stringify!($state)))?
    };
}

pub fn check_state_invariants<'a, BS: Blockstore + Debug>(
    manifest: &Manifest,
    policy: &Policy,
    tree: Tree<'a, BS>,
    expected_balance_total: &TokenAmount,
    prior_epoch: ChainEpoch,
) -> anyhow::Result<()> {
    let acc = MessageAccumulator::default();
    let mut total_fil = BigInt::zero();

    let mut init_summary: Option<init::StateSummary> = None;
    let mut cron_summary: Option<cron::StateSummary> = None;
    let mut account_summaries = Vec::<account::StateSummary>::new();
    let mut power_summary: Option<power::StateSummary> = None;
    let mut miner_summaries = HashMap::<Address, miner::StateSummary>::new();
    let mut market_summary: Option<market::StateSummary> = None;
    let mut paych_summaries = Vec::<paych::StateSummary>::new();
    let mut multisig_summaries = Vec::<multisig::StateSummary>::new();
    let mut reward_summary: Option<reward::StateSummary> = None;
    let mut verifreg_summary: Option<verifreg::StateSummary> = None;

    tree.for_each(|key, actor| {
        let acc = acc.with_prefix(format!("{key} "));

        if key.protocol() != Protocol::ID {
            acc.add(format!("unexpected address protocol in state tree root: {key}"));
        }
        total_fil += &actor.balance;

        match manifest.get_by_left(&actor.code) {
            Some(Type::System) => (),
            Some(Type::Init) => {
                let state = get_state!(tree, actor, InitState);
                let (summary, msgs) = init::check_state_invariants(&state, tree.store);
                acc.with_prefix("init: ").add_all(&msgs);
                init_summary = Some(summary);
            }
            Some(Type::Cron) => {
                let state = get_state!(tree, actor, CronState);
                let (summary, msgs) = cron::check_state_invariants(&state);
                acc.with_prefix("cron: ").add_all(&msgs);
                cron_summary = Some(summary);
            }
            Some(Type::Account) => {
                let state = get_state!(tree, actor, AccountState);
                let (summary, msgs) = account::check_state_invariants(&state, key);
                acc.with_prefix("account: ").add_all(&msgs);
                account_summaries.push(summary);
            }
            Some(Type::Power) => {
                let state = get_state!(tree, actor, PowerState);
                let (summary, msgs) = power::check_state_invariants(policy, &state, tree.store);
                acc.with_prefix("power: ").add_all(&msgs);
                power_summary = Some(summary);
            }
            Some(Type::Miner) => {
                let state = get_state!(tree, actor, MinerState);
                let (summary, msgs) =
                    miner::check_state_invariants(policy, &state, tree.store, &actor.balance);
                acc.with_prefix("miner: ").add_all(&msgs);
                miner_summaries.insert(key.clone(), summary);
            }
            Some(Type::Market) => {
                let state = get_state!(tree, actor, MarketState);
                let (summary, msgs) =
                    market::check_state_invariants(&state, tree.store, &actor.balance, prior_epoch);
                acc.with_prefix("market: ").add_all(&msgs);
                market_summary = Some(summary);
            }
            Some(Type::PaymentChannel) => {
                let state = get_state!(tree, actor, PaychState);
                let (summary, msgs) =
                    paych::check_state_invariants(&state, tree.store, &actor.balance);
                acc.with_prefix("paych: ").add_all(&msgs);
                paych_summaries.push(summary);
            }
            Some(Type::Multisig) => {
                let state = get_state!(tree, actor, MultisigState);
                let (summary, msgs) = multisig::check_state_invariants(&state, tree.store);
                acc.with_prefix("multisig: ").add_all(&msgs);
                multisig_summaries.push(summary);
            }
            Some(Type::Reward) => {
                let state = get_state!(tree, actor, RewardState);
                let (summary, msgs) =
                    reward::check_state_invariants(&state, prior_epoch, &actor.balance);
                acc.with_prefix("reward: ").add_all(&msgs);
                reward_summary = Some(summary);
            }
            Some(Type::VerifiedRegistry) => {
                let state = get_state!(tree, actor, VerifregState);
                let (summary, msgs) = verifreg::check_state_invariants(&state, tree.store);
                acc.with_prefix("verifreg: ").add_all(&msgs);
                verifreg_summary = Some(summary);
            }
            None => {
                bail!("unexpected actor code CID {} for address {}", actor.code, key);
            }
        };

        Ok(())
    })

    // Perform cross-actor checks from state summaries here.
}
