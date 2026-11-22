// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::common::{ConfirmedTx, FilterQueue, SyncState};
use crate::error::{InternalError, TxSyncError};

use electrum_client::utils::validate_merkle_proof;
use electrum_client::Client as ElectrumClient;
use electrum_client::ElectrumApi;

use lightning::chain::WatchedOutput;
use lightning::chain::{Confirm, Filter};
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_trace};

use bitcoin::block::Header;
use bitcoin::{BlockHash, Script, Transaction, Txid};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Synchronizes LDK with a given Electrum server.
///
/// Needs to be registered with a [`ChainMonitor`] via the [`Filter`] interface to be informed of
/// transactions and outputs to monitor for on-chain confirmation, unconfirmation, and
/// reconfirmation.
///
/// Note that registration via [`Filter`] needs to happen before any calls to
/// [`Watch::watch_channel`] to ensure we get notified of the items to monitor.
///
/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
/// [`Watch::watch_channel`]: lightning::chain::Watch::watch_channel
/// [`Filter`]: lightning::chain::Filter
pub struct ElectrumSyncClient<L: Logger> {
	sync_state: Mutex<SyncState>,
	queue: Mutex<FilterQueue>,
	client: Arc<ElectrumClient>,
	logger: L,
}

impl<L: Logger> ElectrumSyncClient<L> {
	/// Returns a new [`ElectrumSyncClient`] object.
	pub fn new(server_url: String, logger: L) -> Result<Self, TxSyncError> {
		let client = Arc::new(ElectrumClient::new(&server_url).map_err(|e| {
			log_error!(logger, "Failed to connect to electrum server '{}': {}", server_url, e);
			e
		})?);

		Self::from_client(client, logger)
	}

	/// Returns a new [`ElectrumSyncClient`] object using the given Electrum client.
	///
	/// This is not exported to bindings users as the underlying client from BDK is not exported.
	pub fn from_client(client: Arc<ElectrumClient>, logger: L) -> Result<Self, TxSyncError> {
		let sync_state = Mutex::new(SyncState::new());
		let queue = Mutex::new(FilterQueue::new());

		Ok(Self { sync_state, queue, client, logger })
	}

	/// Synchronizes the given `confirmables` via their [`Confirm`] interface implementations. This
	/// method should be called regularly to keep LDK up-to-date with current chain data.
	///
	/// For example, instances of [`ChannelManager`] and [`ChainMonitor`] can be informed about the
	/// newest on-chain activity related to the items previously registered via the [`Filter`]
	/// interface.
	///
	/// [`Confirm`]: lightning::chain::Confirm
	/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	/// [`Filter`]: lightning::chain::Filter
	pub fn sync<C: Deref>(&self, confirmables: Vec<C>) -> Result<(), TxSyncError>
	where
		C::Target: Confirm,
	{
		// This lock makes sure we're syncing once at a time.
		let mut sync_state = self.sync_state.lock().unwrap();

		log_trace!(self.logger, "Starting transaction sync.");
		#[cfg(feature = "time")]
		let start_time = Instant::now();
		let mut num_confirmed = 0;
		let mut num_unconfirmed = 0;

		// Clear any header notifications we might have gotten to keep the queue count low.
		while let Some(_) = self.client.block_headers_pop()? {}

		let tip_notification = self.client.block_headers_subscribe()?;
		let mut tip_header = tip_notification.header;
		let mut tip_height = tip_notification.height as u32;

		for i in 0..100 {
			if i >= 10 {
				log_debug!(self.logger, "Giving up trying to sync transactions after 10 attempts.");
				sync_state.pending_sync = true;
				return Err(TxSyncError::Failed);
			}

			let pending_registrations = self.queue.lock().unwrap().process_queues(&mut sync_state);
			let tip_is_new = Some(tip_header.block_hash()) != sync_state.last_sync_hash;

			// We loop until any registered transactions have been processed at least once, or the
			// tip hasn't been updated during the last iteration.
			if !sync_state.pending_sync && !pending_registrations && !tip_is_new {
				// Nothing to do.
				break;
			} else {
				// Update the known tip to the newest one.
				if tip_is_new {
					// First check for any unconfirmed transactions and act on it immediately.
					match self.get_unconfirmed_transactions(&confirmables) {
						Ok(unconfirmed_txs) => {
							// Double-check the tip hash. If it changed, a reorg happened since
							// we started syncing and we need to restart last-minute.
							match self.check_update_tip(&mut tip_header, &mut tip_height) {
								Ok(false) => {
									num_unconfirmed += unconfirmed_txs.len();
									sync_state.sync_unconfirmed_transactions(
										&confirmables,
										unconfirmed_txs,
									);
								},
								Ok(true) => {
									log_debug!(self.logger,
										"Encountered inconsistency during transaction sync, restarting.");
									sync_state.pending_sync = true;
									continue;
								},
								Err(err) => {
									// (Semi-)permanent failure, retry later.
									log_error!(self.logger,
										"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
										num_confirmed,
										num_unconfirmed
									);
									sync_state.pending_sync = true;
									return Err(TxSyncError::from(err));
								},
							}
						},
						Err(err) => {
							// (Semi-)permanent failure, retry later.
							log_error!(self.logger,
								"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
								num_confirmed,
								num_unconfirmed
							);
							sync_state.pending_sync = true;
							return Err(TxSyncError::from(err));
						},
					}

					// Update the best block.
					for c in &confirmables {
						c.best_block_updated(&tip_header, tip_height);
					}

					// Prune any sufficiently confirmed output spends
					sync_state.prune_output_spends(tip_height);
				}

				match self.get_confirmed_transactions(&sync_state) {
					Ok(confirmed_txs) => {
						// Double-check the tip hash. If it changed, a reorg happened since
						// we started syncing and we need to restart last-minute.
						match self.check_update_tip(&mut tip_header, &mut tip_height) {
							Ok(false) => {
								num_confirmed += confirmed_txs.len();
								sync_state
									.sync_confirmed_transactions(&confirmables, confirmed_txs);
							},
							Ok(true) => {
								log_debug!(self.logger,
									"Encountered inconsistency during transaction sync, restarting.");
								sync_state.pending_sync = true;
								continue;
							},
							Err(err) => {
								// (Semi-)permanent failure, retry later.
								log_error!(self.logger,
									"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
									num_confirmed,
									num_unconfirmed
								);
								sync_state.pending_sync = true;
								return Err(TxSyncError::from(err));
							},
						}
					},
					Err(InternalError::Inconsistency) => {
						// Immediately restart syncing when we encounter any inconsistencies.
						log_debug!(
							self.logger,
							"Encountered inconsistency during transaction sync, restarting."
						);
						sync_state.pending_sync = true;
						continue;
					},
					Err(err) => {
						// (Semi-)permanent failure, retry later.
						log_error!(self.logger,
							"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
							num_confirmed,
							num_unconfirmed
						);
						sync_state.pending_sync = true;
						return Err(TxSyncError::from(err));
					},
				}
				sync_state.last_sync_hash = Some(tip_header.block_hash());
				sync_state.pending_sync = false;
			}
		}
		#[cfg(feature = "time")]
		log_debug!(
			self.logger,
			"Finished transaction sync at tip {} in {}ms: {} confirmed, {} unconfirmed.",
			tip_header.block_hash(),
			start_time.elapsed().as_millis(),
			num_confirmed,
			num_unconfirmed
		);
		#[cfg(not(feature = "time"))]
		log_debug!(
			self.logger,
			"Finished transaction sync at tip {}: {} confirmed, {} unconfirmed.",
			tip_header.block_hash(),
			num_confirmed,
			num_unconfirmed
		);
		Ok(())
	}

	fn check_update_tip(
		&self, cur_tip_header: &mut Header, cur_tip_height: &mut u32,
	) -> Result<bool, InternalError> {
		let check_notification = self.client.block_headers_subscribe()?;
		let check_tip_hash = check_notification.header.block_hash();

		// Restart if either the tip changed or we got some divergent tip
		// change notification since we started. In the latter case we
		// make sure we clear the queue before continuing.
		let mut restart_sync = check_tip_hash != cur_tip_header.block_hash();
		while let Some(queued_notif) = self.client.block_headers_pop()? {
			if queued_notif.header.block_hash() != check_tip_hash {
				restart_sync = true
			}
		}

		if restart_sync {
			*cur_tip_header = check_notification.header;
			*cur_tip_height = check_notification.height as u32;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	// Blocknil patch (rl-22): the requests below are sent in batches instead of one at a time.
	//
	// What is checked is unchanged: every fetched transaction is compared with the txid asked for,
	// every Merkle proof is validated against its block header, and the tip is re-checked around
	// each phase by `sync`. What changed is only how many times we wait on the server: before, each
	// watched transaction cost a `transaction_get`, each confirmed one a `transaction_get_merkle`
	// plus a `block_header`, each spend of a watched output a further `transaction_get`, and each
	// known confirmation a `block_header`, all sequential. On a phone talking to a server ~150 ms
	// away that was ~28 round trips and ~4.8 s on every node start for a wallet with one open and
	// one recently closed channel (Blocknil, 2026-11-22). Batched, a sync costs a fixed ~9 round
	// trips however many transactions are watched.
	fn get_confirmed_transactions(
		&self, sync_state: &SyncState,
	) -> Result<Vec<ConfirmedTx>, InternalError> {
		// First, check the confirmation status of registered transactions as well as the
		// status of dependent transactions of registered outputs.
		let mut watched_script_pubkeys = Vec::with_capacity(
			sync_state.watched_transactions.len() + sync_state.watched_outputs.len(),
		);
		let mut watched_txs = Vec::with_capacity(sync_state.watched_transactions.len());

		let registered: Vec<_> = sync_state.watched_transactions.iter().collect();
		let registered_txids: Vec<&Txid> = registered.iter().map(|(txid, _)| *txid).collect();
		let fetched = self.fetch_watched_transactions(&registered_txids)?;

		for ((txid, watch_script_pubkeys), fetched_tx) in registered.into_iter().zip(fetched) {
			// `None`: the server doesn't know the transaction, do nothing (as before).
			let tx = match fetched_tx {
				Some(tx) => tx,
				None => continue,
			};
			if tx.compute_txid() != *txid {
				log_error!(self.logger, "Retrieved transaction for txid {} doesn't match expectations. This should not happen. Please verify server integrity.", txid);
				return Err(InternalError::Failed);
			}

			// We watch an output's script_pubkey of the transaction of interest in order
			// to retrieve the associated script history, before narrowing down our search
			// through `filter`ing by `txid` below. Prefer a script_pubkey the transaction
			// was registered with that actually appears in the transaction (as registered
			// script_pubkeys may be bogus), and otherwise pick an arbitrary one, noting
			// that electrum servers may not index OP_RETURN script_pubkeys at all.
			let candidate_outputs =
				tx.output.iter().filter(|output| !output.script_pubkey.is_op_return());
			let watch_output = candidate_outputs
				.clone()
				.find(|output| watch_script_pubkeys.contains(&output.script_pubkey))
				.or_else(|| candidate_outputs.clone().next())
				.or_else(|| tx.output.iter().next());
			if let Some(tx_out) = watch_output {
				watched_script_pubkeys.push(tx_out.script_pubkey.clone());
			} else {
				debug_assert!(false, "Failed due to retrieving invalid tx data.");
				log_error!(self.logger, "Failed due to retrieving invalid tx data.");
				return Err(InternalError::Failed);
			}
			watched_txs.push((txid, tx));
		}

		let num_tx_lookups = watched_script_pubkeys.len();
		debug_assert_eq!(num_tx_lookups, watched_txs.len());

		for script_pubkey in sync_state.watched_outputs.values().flatten() {
			watched_script_pubkeys.push(script_pubkey.clone());
		}

		let num_output_spend_lookups = watched_script_pubkeys.len() - num_tx_lookups;
		debug_assert_eq!(
			num_output_spend_lookups,
			sync_state.watched_outputs.values().flatten().count()
		);

		// Transactions found confirmed, with the height the server says, whose proofs are fetched
		// and checked together at the end (`get_confirmed_txs`).
		let mut candidates: Vec<(Txid, Transaction, u32)> = Vec::new();

		match self.client.batch_script_get_history(watched_script_pubkeys.iter().map(|s| s.deref()))
		{
			Ok(results) => {
				let (tx_results, output_results) = results.split_at(num_tx_lookups);
				debug_assert_eq!(num_output_spend_lookups, output_results.len());

				for (i, script_history) in tx_results.iter().enumerate() {
					let (txid, tx) = &watched_txs[i];
					if candidates.iter().any(|(ctxid, _, _)| *ctxid == **txid) {
						continue;
					}
					let mut filtered_history =
						script_history.iter().filter(|h| h.tx_hash == **txid);
					if let Some(history) = filtered_history.next() {
						if history.height <= 0 {
							// Skip if it's a an unconfirmed entry.
							continue;
						}
						candidates.push((**txid, tx.clone(), history.height as u32));
					}
					if filtered_history.next().is_some() {
						log_error!(
							self.logger,
							"Failed due to server returning multiple history entries for Tx {}.",
							txid
						);
						return Err(InternalError::Failed);
					}
				}

				let watched_outpoints =
					sync_state.watched_outputs.iter().flat_map(|(outpoint, script_pubkeys)| {
						script_pubkeys.iter().map(move |_| outpoint)
					});
				let possible_spends: Vec<_> = watched_outpoints
					.zip(output_results)
					.flat_map(|(watched_outpoint, script_history)| {
						script_history
							.iter()
							// Skip unconfirmed entries.
							.filter(|h| h.height > 0)
							.map(move |h| (watched_outpoint, h.tx_hash, h.height as u32))
					})
					.collect();

				// Every transaction that may spend a watched output, fetched in one batch: before,
				// one `transaction_get` each.
				let mut spend_txids: Vec<Txid> = Vec::new();
				for (_, txid, _) in &possible_spends {
					let known = candidates.iter().any(|(ctxid, _, _)| ctxid == txid);
					if !known && !spend_txids.contains(txid) {
						spend_txids.push(*txid);
					}
				}
				let spend_txs = match self.client.batch_transaction_get(spend_txids.iter()) {
					Ok(txs) if txs.len() == spend_txids.len() => txs,
					Ok(_) => {
						log_error!(self.logger, "Failed due to the server answering a different number of transactions than asked for.");
						return Err(InternalError::Failed);
					},
					Err(e) => {
						log_trace!(
							self.logger,
							"Inconsistency: a possible spend was unconfirmed during syncing: {}",
							e
						);
						return Err(InternalError::Inconsistency);
					},
				};

				// Then, in the same order as before, which of them spend the watched outputs.
				for (watched_outpoint, txid, prob_conf_height) in possible_spends {
					if candidates.iter().any(|(ctxid, _, _)| *ctxid == txid) {
						continue;
					}
					let tx = match spend_txids.iter().position(|t| *t == txid) {
						Some(i) => &spend_txs[i],
						None => continue,
					};
					if tx.compute_txid() != txid {
						log_error!(self.logger, "Retrieved transaction for txid {} doesn't match expectations. This should not happen. Please verify server integrity.", txid);
						return Err(InternalError::Failed);
					}

					let is_spend =
						tx.input.iter().any(|txin| txin.previous_output == *watched_outpoint);
					if !is_spend {
						continue;
					}

					candidates.push((txid, tx.clone(), prob_conf_height));
				}
			},
			Err(e) => {
				log_error!(self.logger, "Failed to look up script histories: {}.", e);
				return Err(InternalError::Failed);
			},
		}

		let mut confirmed_txs = self.get_confirmed_txs(candidates)?;

		// Sort all confirmed transactions first by block height, then by in-block
		// position, and finally feed them to the interface in order.
		confirmed_txs.sort_unstable_by(|tx1, tx2| {
			tx1.block_height.cmp(&tx2.block_height).then_with(|| tx1.pos.cmp(&tx2.pos))
		});

		Ok(confirmed_txs)
	}

	/// The registered transactions, in the order of `txids`; `None` for one the server doesn't
	/// know.
	///
	/// One batch normally. A server that doesn't know one transaction answers that item with an
	/// error, and the client then fails the whole batch with `Error::Protocol`, so in that case the
	/// transactions are asked for one at a time, exactly as before rl-22, to skip only the
	/// unknown one.
	fn fetch_watched_transactions(
		&self, txids: &[&Txid],
	) -> Result<Vec<Option<Transaction>>, InternalError> {
		match self.client.batch_transaction_get(txids.iter().copied()) {
			Ok(txs) if txs.len() == txids.len() => Ok(txs.into_iter().map(Some).collect()),
			Ok(_) => {
				log_error!(self.logger, "Failed due to the server answering a different number of transactions than asked for.");
				Err(InternalError::Failed)
			},
			Err(electrum_client::Error::Protocol(_)) => {
				let mut fetched = Vec::with_capacity(txids.len());
				for txid in txids {
					match self.client.transaction_get(txid) {
						Ok(tx) => fetched.push(Some(tx)),
						Err(electrum_client::Error::Protocol(_)) => {
							// We couldn't find the tx, do nothing.
							fetched.push(None)
						},
						Err(e) => {
							log_error!(
								self.logger,
								"Failed to look up transaction {}: {}.",
								txid,
								e
							);
							return Err(InternalError::Failed);
						},
					}
				}
				Ok(fetched)
			},
			Err(e) => {
				log_error!(self.logger, "Failed to look up transactions: {}.", e);
				Err(InternalError::Failed)
			},
		}
	}

	fn get_unconfirmed_transactions<C: Deref>(
		&self, confirmables: &Vec<C>,
	) -> Result<Vec<Txid>, InternalError>
	where
		C::Target: Confirm,
	{
		// Query the interface for relevant txids and check whether the relevant blocks are still
		// in the best chain, mark them unconfirmed otherwise
		let relevant_txids = confirmables
			.iter()
			.flat_map(|c| c.get_relevant_txids())
			.collect::<HashSet<(Txid, u32, Option<BlockHash>)>>();

		let mut to_check = Vec::with_capacity(relevant_txids.len());
		for (txid, conf_height, block_hash_opt) in relevant_txids {
			if let Some(block_hash) = block_hash_opt {
				to_check.push((txid, conf_height, block_hash));
			} else {
				log_error!(self.logger,
					"Untracked confirmation of funding transaction. Please ensure none of your channels had been created with LDK prior to version 0.0.113!");
				panic!("Untracked confirmation of funding transaction. Please ensure none of your channels had been created with LDK prior to version 0.0.113!");
			}
		}

		// The headers at every height we need, in one batch: before, one `block_header` each.
		let heights: Vec<u32> =
			to_check.iter().map(|(_, h, _)| *h).collect::<BTreeSet<_>>().into_iter().collect();
		let hashes = self.block_hashes_at(&heights)?;

		let mut unconfirmed_txs = Vec::new();
		for (txid, conf_height, block_hash) in to_check {
			// Skip if the tx is still confirmed in the block in question.
			if hashes.get(&conf_height).map(|(hash, _)| *hash) != Some(block_hash) {
				unconfirmed_txs.push(txid);
			}
		}
		Ok(unconfirmed_txs)
	}

	/// The block header at each of `heights`, with its hash, from one batch.
	fn block_hashes_at(
		&self, heights: &[u32],
	) -> Result<HashMap<u32, (BlockHash, Header)>, electrum_client::Error> {
		let headers = self.client.batch_block_header(heights)?;
		if headers.len() != heights.len() {
			return Err(electrum_client::Error::InvalidResponse(
				"a different number of headers than asked for".into(),
			));
		}
		Ok(heights.iter().copied().zip(headers.into_iter().map(|h| (h.block_hash(), h))).collect())
	}

	/// Checks that each candidate is in the block at the height the server gave, and builds its
	/// `ConfirmedTx`. The proofs come in one batch and the headers in another: before rl-22, each
	/// candidate cost a `transaction_get_merkle` and a `block_header` of its own.
	fn get_confirmed_txs(
		&self, candidates: Vec<(Txid, Transaction, u32)>,
	) -> Result<Vec<ConfirmedTx>, InternalError> {
		if candidates.is_empty() {
			return Ok(Vec::new());
		}

		let proof_requests: Vec<(Txid, usize)> =
			candidates.iter().map(|(txid, _, height)| (*txid, *height as usize)).collect();
		let proofs = match self.client.batch_transaction_get_merkle(&proof_requests) {
			Ok(proofs) if proofs.len() == candidates.len() => proofs,
			Ok(_) => {
				log_error!(self.logger, "Failed due to the server answering a different number of proofs than asked for.");
				return Err(InternalError::Failed);
			},
			Err(e) => {
				log_trace!(
					self.logger,
					"Inconsistency: a transaction was unconfirmed during syncing: {}",
					e
				);
				return Err(InternalError::Inconsistency);
			},
		};

		let heights: Vec<u32> =
			candidates.iter().map(|(_, _, h)| *h).collect::<BTreeSet<_>>().into_iter().collect();
		let headers = match self.block_hashes_at(&heights) {
			Ok(headers) => headers,
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to retrieve block headers at heights {:?}: {}.",
					heights,
					e
				);
				return Err(InternalError::Failed);
			},
		};

		let mut confirmed_txs = Vec::with_capacity(candidates.len());
		for ((txid, tx, prob_conf_height), merkle_res) in candidates.into_iter().zip(proofs) {
			debug_assert_eq!(prob_conf_height, merkle_res.block_height as u32);
			let block_header = match headers.get(&prob_conf_height) {
				Some((_, header)) => *header,
				None => return Err(InternalError::Failed),
			};
			if !validate_merkle_proof(&txid, &block_header.merkle_root, &merkle_res) {
				log_trace!(
					self.logger,
					"Inconsistency: Block {} was unconfirmed during syncing.",
					block_header.block_hash()
				);
				return Err(InternalError::Inconsistency);
			}
			confirmed_txs.push(ConfirmedTx {
				tx,
				txid,
				block_header,
				block_height: prob_conf_height,
				pos: merkle_res.pos,
			});
		}
		Ok(confirmed_txs)
	}

	/// Returns a reference to the underlying Electrum client.
	///
	/// This is not exported to bindings users as the underlying client from BDK is not exported.
	pub fn client(&self) -> Arc<ElectrumClient> {
		Arc::clone(&self.client)
	}
}

impl<L: Logger> Filter for ElectrumSyncClient<L> {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		let mut locked_queue = self.queue.lock().unwrap();
		let script_pubkeys = locked_queue.transactions.entry(*txid).or_default();
		if script_pubkeys.iter().all(|spk| spk != script_pubkey) {
			script_pubkeys.push(script_pubkey.to_owned());
		}
	}

	fn register_output(&self, output: WatchedOutput) {
		let mut locked_queue = self.queue.lock().unwrap();
		locked_queue
			.outputs
			.entry(output.outpoint.into_bitcoin_outpoint())
			.or_default()
			.insert(output.script_pubkey);
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn transaction_get_responses_are_verified_at_call_sites() {
		let src = include_str!("electrum.rs");
		let watched_transaction_check = concat!("if tx.compute_", "txid() != *txid");
		let watched_output_spend_check = concat!("if tx.compute_", "txid() != txid");

		assert!(
			src.contains(watched_transaction_check),
			"watched transaction_get responses must be verified against the requested txid"
		);
		assert!(
			src.contains(watched_output_spend_check),
			"watched-output spend transaction_get responses must be verified against the \
			 requested txid"
		);
	}
}
