use std::{
    collections::{hash_map::Entry, HashMap},
    future,
    ops::{Deref, DerefMut},
};

use super::{error::BlockchainError, storage::Storage};
use chacha20poly1305::Key;
use futures::{
    stream, stream::futures_unordered::FuturesUnordered, FutureExt, StreamExt, TryFutureExt,
    TryStreamExt,
};
use xelis_common::{
    account::VersionedBalance,
    crypto::{elgamal::CompressedPublicKey, Hash, PublicKey},
    transaction::{
        verify::{BlockchainVerificationState, CachedCiphertext},
        Transaction,
    },
};

#[derive(Clone, Debug, Default, Copy)]
struct Updatable<T> {
    inner: T,
    modified: bool,
}
impl<T: ?Sized + Clone> Updatable<T> {
    fn new(inner: T) -> Self
    where
        T: Sized,
    {
        Self {
            inner,
            modified: false,
        }
    }

    fn is_modified(&self) -> bool {
        self.modified
    }
}
impl<T: ?Sized + Clone> Deref for Updatable<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl<T: ?Sized + Clone> DerefMut for Updatable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.modified = true;
        &mut self.inner
    }
}

#[derive(Clone, Default)]
pub struct CachedVersionedBalance {
    // Output balance is used in case of multi TXs not in same block
    // If you build several TXs at same time but are not in the same block,
    // and a incoming tx happen we need to keep track of the output balance
    output_balance: Option<CachedCiphertext>,
    // Final user balance that contains outputs and inputs balance
    // This is the balance shown to a user and used to build TXs
    final_balance: CachedCiphertext,
    previous_topoheight: Option<u64>,
}

impl From<CachedVersionedBalance> for VersionedBalance {
    fn from(value: CachedVersionedBalance) -> Self {
        let mut v = Self::new(value.final_balance.into(), value.previous_topoheight);
        if let Some(bal) = value.output_balance {
            v.set_output_balance(bal.into())
        }
        v
    }
}

impl CachedVersionedBalance {
    pub fn effective_balance(&self) -> &CachedCiphertext {
        self.output_balance.as_ref().unwrap_or(&self.final_balance)
    }

    pub fn update_balance(&mut self, ct: CachedCiphertext) {
        self.output_balance = Some(ct)
    }
}

#[derive(Default, Clone)]
struct CachedAccount {
    balances: HashMap<Hash, Updatable<CachedVersionedBalance>>,
}

impl CachedAccount {
    /// Init this account by fetching it from `storage`.
    pub async fn init_for_account<S: Storage>(
        &mut self,
        storage: &S,
        key: &PublicKey,
        topoheight: u64,
    ) -> Result<(), ()> {
        // TODO: modify self to fetch account's info from storage
        todo!()
    }
}

#[derive(Clone)]
struct CachedState {
    /// topoheight on which this state is based
    topoheight: u64,
    balances: HashMap<PublicKey, Updatable<CachedAccount>>,
    nonces: HashMap<PublicKey, Updatable<u64>>,
}

impl CachedState {
    pub async fn init_from_storage_for_tx<S: Storage>(
        &mut self,
        storage: &S,
        tx: &Transaction,
    ) -> Result<(), ()> {
        // get all accounts from db in parallel
        let accounts = tx
            .get_modified_accounts()
            .map(|(_, key)| async {
                let acc = CachedAccount::default();
                CachedAccount::default()
                    .init_for_account(storage, key, self.topoheight)
                    .await?;
                Ok((key.clone(), acc))
            })
            .collect::<FuturesUnordered<_>>();

        accounts
            .try_for_each(|(key, account)| {
                self.balances.insert(key, Updatable::new(account));
                future::ready(Ok(()))
            })
            .await?;

        // FIXME: fetch nonces too

        Ok(())
    }

    pub async fn apply_updates<S: Storage>(
        &self,
        storage: &mut S,
        topoheight: u64,
    ) -> Result<(), BlockchainError> {
        let bals = self
            .balances
            .iter()
            .filter(|(_, u)| u.is_modified())
            .flat_map(|(key, account)| {
                account
                    .balances
                    .iter()
                    .filter(|(_, u)| u.is_modified())
                    .map(move |(asset, bal)| (key, asset, bal))
            });

        for (key, asset, bal) in bals {
            storage.set_last_balance_to(key, asset, topoheight, &bal.deref().clone().into()).await?
        }

        let nonces = self.nonces.iter().filter(|(_, u)| u.is_modified());

        for (key, nonce) in nonces {
            // storage.set_nonce_at_topoheight(key, topoheight, **nonce).await?
            // FIXME
        }
        Ok(())
    }
}

impl BlockchainVerificationState for CachedState {
    type Error = ();

    /// Get the balance ciphertext for a receiver account
    fn get_balance(
        &self,
        account: &CompressedPublicKey,
        asset: &Hash,
    ) -> Result<CachedCiphertext, Self::Error> {
        // If account is not fetched, this means it doesnt exist. Return the zero ct.
        let Some(account) = self.balances.get(account) else {
            return Ok(CachedCiphertext::default());
        };
        let Some(bal) = account.balances.get(asset) else {
            return Ok(CachedCiphertext::default());
        };
        Ok(bal.effective_balance().clone())
    }

    fn update_balance(
        &mut self,
        account: &CompressedPublicKey,
        asset: &Hash,
        new_balance: CachedCiphertext,
    ) -> Result<(), Self::Error> {
        let account = match self.balances.entry(account.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Default::default()),
        };

        let bal = match account.balances.entry(asset.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Default::default()),
        };

        bal.update_balance(new_balance);
        Ok(())
    }

    fn get_account_nonce(&self, account: &CompressedPublicKey) -> Result<u64, Self::Error> {
        // Default accout nonce is 0
        Ok(self.nonces.get(account).map(|e| **e).unwrap_or(0))
    }

    fn update_account_nonce(
        &mut self,
        account: &CompressedPublicKey,
        new_nonce: u64,
    ) -> Result<(), Self::Error> {
        let nonce = match self.nonces.entry(account.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Default::default()),
        };

        **nonce = new_nonce;
        Ok(())
    }
}
