//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tokio::sync::oneshot::Sender as Responder;
use yang3::data::{DataDiff, DataTree};

use crate::northbound::Result;
use crate::northbound::core::Transaction;

// Daemon -> External client requests.
pub mod daemon {}

// External client -> Daemon requests.
pub mod client {
    use super::*;

    #[derive(Debug)]
    pub enum Request {
        // Request to get data (configuration, state or both).
        Get(GetRequest),
        // Request to validate a candidate configuration.
        Validate(ValidateRequest),
        // Request to change the running configuration.
        Commit(CommitRequest),
        // Request to invoke a YANG RPC or Action.
        Execute(ExecuteRequest),
        // Request to get the list of transactions recorded in the rollback
        // log.
        ListTransactions(ListTransactionsRequest),
        // Request to retrieve configuration data from the rollback log.
        GetTransaction(GetTransactionRequest),
    }

    #[derive(Debug)]
    pub struct GetRequest {
        pub data_type: DataType,
        pub path: Option<String>,
        pub responder: Responder<Result<GetResponse>>,
    }

    #[derive(Debug)]
    pub struct GetResponse {
        pub dtree: DataTree<'static>,
    }

    #[derive(Debug)]
    pub struct ValidateRequest {
        pub config: DataTree<'static>,
        pub responder: Responder<Result<ValidateResponse>>,
    }

    #[derive(Debug)]
    pub struct ValidateResponse {}

    #[derive(Debug)]
    pub struct CommitRequest {
        pub config: CommitConfiguration,
        pub comment: String,
        pub confirmed_timeout: u32,
        pub responder: Responder<Result<CommitResponse>>,
    }

    #[derive(Debug)]
    pub struct CommitResponse {
        pub transaction_id: u32,
    }

    #[derive(Debug)]
    pub struct ExecuteRequest {
        pub data: DataTree<'static>,
        pub responder: Responder<Result<ExecuteResponse>>,
    }

    #[derive(Debug)]
    pub struct ExecuteResponse {
        pub data: DataTree<'static>,
    }

    #[derive(Debug)]
    pub struct ListTransactionsRequest {
        pub responder: Responder<Result<ListTransactionsResponse>>,
    }

    #[derive(Debug)]
    pub struct ListTransactionsResponse {
        pub transactions: Vec<Transaction>,
    }

    #[derive(Debug)]
    pub struct GetTransactionRequest {
        pub transaction_id: u32,
        pub responder: Responder<Result<GetTransactionResponse>>,
    }

    #[derive(Debug)]
    pub struct GetTransactionResponse {
        pub dtree: DataTree<'static>,
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DataType {
    All,
    Configuration,
    State,
}

#[derive(Debug)]
pub enum CommitConfiguration {
    Merge(DataTree<'static>),
    Replace(DataTree<'static>),
    Change(DataDiff<'static>),
}
