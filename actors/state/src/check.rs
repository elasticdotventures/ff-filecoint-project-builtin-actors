use anyhow::bail;
use cid::Cid;
use fil_actor_init::State as InitState;
use fil_actor_cron::State as CronState;
use fil_actor_account::State as AccountState;
use fil_actor_power::State as PowerState;
use fil_actor_miner::State as MinerState;
use fil_actor_market::State as MarketState;
use fil_actor_paych::State as PaychState;
use fil_actor_multisig::State as MultisigState;
use fil_actor_reward::State as RewardState;
use fil_actor_verifreg::State as VerifregState;
use fil_actors_runtime::Map;
use fil_actors_runtime::MessageAccumulator;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::CborStore;
use fvm_shared::actor::builtin::Manifest;
use fvm_shared::actor::builtin::Type;
use fvm_shared::address::Address;
use fvm_shared::address::Protocol;
use fvm_shared::bigint::BigInt;
use fvm_shared::econ::TokenAmount;
use num_traits::Zero;

use anyhow::anyhow;
use fvm_ipld_encoding::tuple::*;
use fvm_shared::bigint::bigint_ser;

use fil_actor_init::testing as init;
use fil_actor_cron::testing as cron;
use fil_actor_account::testing as account;
use fil_actor_power::testing as power;
use fil_actor_miner::testing as miner;
use fil_actor_market::testing as market;
use fil_actor_paych::testing as paych;
use fil_actor_multisig::testing as multisig;
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

pub fn check_state_invariants<'a, BS: Blockstore>(
    manifest: &Manifest,
    tree: Tree<'a, BS>,
) -> anyhow::Result<()> {
    let acc = MessageAccumulator::default();
    let mut total_fil = BigInt::zero();

    let mut init_summary: Option<init::StateSummary> = None;

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
            }
            Some(Type::Account) => {}
            Some(Type::Power) => {}
            Some(Type::Miner) => {}
            Some(Type::Market) => {}
            Some(Type::PaymentChannel) => {}
            Some(Type::Multisig) => {}
            Some(Type::Reward) => {}
            Some(Type::VerifiedRegistry) => {}
            None => {
                bail!("unexpected actor code CID {} for address {}", actor.code, key);
            }
        };

        Ok(())
    })
}
