//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::time::{Duration, Instant};

use chrono::Utc;
use derive_new::new;
use holo_utils::task::TimeoutTask;

use crate::adjacency::Adjacency;
use crate::collections::{Arena, Interfaces};
use crate::debug::Debug;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::lsdb::{LspEntry, LspLogId};
use crate::packet::LevelNumber;
use crate::tasks;

// Maximum size of the SPF log record.
const SPF_LOG_MAX_SIZE: usize = 32;
// Maximum number of trigger LSPs per entry in the SPF log record.
const SPF_LOG_TRIGGER_LSPS_MAX_SIZE: usize = 8;

#[derive(Debug, Default)]
pub struct SpfScheduler {
    pub last_event_rcvd: Option<Instant>,
    pub last_time: Option<Instant>,
    pub delay_state: fsm::State,
    pub delay_timer: Option<TimeoutTask>,
    pub hold_down_timer: Option<TimeoutTask>,
    pub learn_timer: Option<TimeoutTask>,
    pub trigger_lsps: Vec<LspLogId>,
    pub schedule_time: Option<Instant>,
}

#[derive(Clone, Copy, Debug)]
pub enum SpfType {
    Full,
    RouteOnly,
}

#[derive(Debug, new)]
pub struct SpfLogEntry {
    pub id: u32,
    pub spf_type: SpfType,
    pub level: LevelNumber,
    pub schedule_time: Instant,
    pub start_time: Instant,
    pub end_time: Instant,
    pub trigger_lsps: Vec<LspLogId>,
}

// SPF Delay State Machine.
pub mod fsm {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
    #[derive(Deserialize, Serialize)]
    pub enum State {
        #[default]
        Quiet,
        ShortWait,
        LongWait,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    pub enum Event {
        Igp,
        DelayTimer,
        HoldDownTimer,
        LearnTimer,
        ConfigChange,
    }
}

// ===== global functions =====

pub(crate) fn fsm(
    level: LevelNumber,
    event: fsm::Event,
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
) -> Result<(), Error> {
    let spf_sched = instance.state.spf_sched.get_mut(level);

    Debug::SpfDelayFsmEvent(level, spf_sched.delay_state, event).log();

    // Update time of last SPF triggering event.
    spf_sched.last_event_rcvd = Some(Instant::now());

    let new_fsm_state = match (spf_sched.delay_state, &event) {
        // Transition 1: IGP event while in QUIET state.
        (fsm::State::Quiet, fsm::Event::Igp) => {
            // If SPF_TIMER is not already running, start it with value
            // INITIAL_SPF_DELAY.
            if spf_sched.delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    level,
                    fsm::Event::DelayTimer,
                    instance.config.spf_initial_delay,
                    &instance.tx.protocol_input.spf_delay_event,
                );
                spf_sched.delay_timer = Some(task);
            }

            // Start LEARN_TIMER with TIME_TO_LEARN_INTERVAL.
            let task = tasks::spf_delay_timer(
                level,
                fsm::Event::LearnTimer,
                instance.config.spf_time_to_learn,
                &instance.tx.protocol_input.spf_delay_event,
            );
            spf_sched.learn_timer = Some(task);

            // Start HOLDDOWN_TIMER with HOLDDOWN_INTERVAL.
            let task = tasks::spf_delay_timer(
                level,
                fsm::Event::HoldDownTimer,
                instance.config.spf_hold_down,
                &instance.tx.protocol_input.spf_delay_event,
            );
            spf_sched.hold_down_timer = Some(task);

            // Transition to SHORT_WAIT state.
            Some(fsm::State::ShortWait)
        }
        // Transition 2: IGP event while in SHORT_WAIT.
        (fsm::State::ShortWait, fsm::Event::Igp) => {
            // Reset HOLDDOWN_TIMER to HOLDDOWN_INTERVAL.
            if let Some(timer) = &mut spf_sched.hold_down_timer {
                let timeout =
                    Duration::from_millis(instance.config.spf_hold_down.into());
                timer.reset(Some(timeout));
            }

            // If SPF_TIMER is not already running, start it with value
            // SHORT_SPF_DELAY.
            if spf_sched.delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    level,
                    fsm::Event::DelayTimer,
                    instance.config.spf_short_delay,
                    &instance.tx.protocol_input.spf_delay_event,
                );
                spf_sched.delay_timer = Some(task);
            }

            // Remain in current state.
            None
        }
        // Transition 3: LEARN_TIMER expiration.
        (fsm::State::ShortWait, fsm::Event::LearnTimer) => {
            spf_sched.learn_timer = None;

            // Transition to LONG_WAIT state.
            Some(fsm::State::LongWait)
        }
        // Transition 4: IGP event while in LONG_WAIT.
        (fsm::State::LongWait, fsm::Event::Igp) => {
            // Reset HOLDDOWN_TIMER to HOLDDOWN_INTERVAL.
            if let Some(timer) = &mut spf_sched.hold_down_timer {
                let timeout =
                    Duration::from_millis(instance.config.spf_hold_down.into());
                timer.reset(Some(timeout));
            }

            // If SPF_TIMER is not already running, start it with value
            // LONG_SPF_DELAY.
            if spf_sched.delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    level,
                    fsm::Event::DelayTimer,
                    instance.config.spf_long_delay,
                    &instance.tx.protocol_input.spf_delay_event,
                );
                spf_sched.delay_timer = Some(task);
            }

            // Remain in current state.
            None
        }
        // Transition 5: HOLDDOWN_TIMER expiration while in LONG_WAIT.
        (fsm::State::LongWait, fsm::Event::HoldDownTimer) => {
            spf_sched.hold_down_timer = None;

            // Transition to QUIET state.
            Some(fsm::State::Quiet)
        }
        // Transition 6: HOLDDOWN_TIMER expiration while in SHORT_WAIT.
        (fsm::State::ShortWait, fsm::Event::HoldDownTimer) => {
            spf_sched.hold_down_timer = None;

            // Deactivate LEARN_TIMER.
            spf_sched.learn_timer = None;

            // Transition to QUIET state.
            Some(fsm::State::Quiet)
        }
        // Transition 7: SPF_TIMER expiration while in QUIET.
        // Transition 8: SPF_TIMER expiration while in SHORT_WAIT.
        // Transition 9: SPF_TIMER expiration while in LONG_WAIT
        (
            fsm::State::Quiet | fsm::State::ShortWait | fsm::State::LongWait,
            fsm::Event::DelayTimer,
        ) => {
            spf_sched.delay_timer = None;

            // Compute SPF.
            compute_spf(
                level,
                instance,
                &arenas.interfaces,
                &arenas.adjacencies,
                &arenas.lsp_entries,
            );

            // Remain in current state.
            None
        }
        // Custom FSM transition.
        (
            fsm::State::Quiet | fsm::State::ShortWait | fsm::State::LongWait,
            fsm::Event::ConfigChange,
        ) => {
            // Cancel the next scheduled SPF run, but preserve the other timers.
            spf_sched.delay_timer = None;

            // Compute SPF.
            compute_spf(
                level,
                instance,
                &arenas.interfaces,
                &arenas.adjacencies,
                &arenas.lsp_entries,
            );

            // Remain in current state.
            None
        }
        _ => {
            return Err(Error::SpfDelayUnexpectedEvent(
                level,
                spf_sched.delay_state,
                event,
            ));
        }
    };

    if let Some(new_fsm_state) = new_fsm_state {
        let spf_sched = instance.state.spf_sched.get_mut(level);
        if new_fsm_state != spf_sched.delay_state {
            // Effectively transition to the new FSM state.
            Debug::SpfDelayFsmTransition(
                level,
                spf_sched.delay_state,
                new_fsm_state,
            )
            .log();
            spf_sched.delay_state = new_fsm_state;
        }
    }

    Ok(())
}

// ===== helper functions =====

// This is the SPF main function.
fn compute_spf(
    level: LevelNumber,
    instance: &mut InstanceUpView<'_>,
    _interfaces: &Interfaces,
    _adjacencies: &Arena<Adjacency>,
    _lsp_entries: &Arena<LspEntry>,
) {
    let spf_sched = instance.state.spf_sched.get_mut(level);

    // Get time the SPF was scheduled.
    let schedule_time =
        spf_sched.schedule_time.take().unwrap_or_else(Instant::now);

    // Record time the SPF computation was started.
    let start_time = Instant::now();

    // Get list of new or updated LSPs that triggered the SPF computation.
    let trigger_lsps = std::mem::take(&mut spf_sched.trigger_lsps);

    // TODO: Run SPF.

    // Update statistics.
    instance.state.counters.get_mut(level).spf_runs += 1;
    instance.state.discontinuity_time = Utc::now();

    // Update time of last SPF computation.
    let end_time = Instant::now();
    spf_sched.last_time = Some(end_time);

    // Add entry to SPF log.
    log_spf_run(
        level,
        instance,
        SpfType::Full,
        schedule_time,
        start_time,
        end_time,
        trigger_lsps,
    );
}

// Adds log entry for the SPF run.
fn log_spf_run(
    level: LevelNumber,
    instance: &mut InstanceUpView<'_>,
    spf_type: SpfType,
    schedule_time: Instant,
    start_time: Instant,
    end_time: Instant,
    mut trigger_lsps: Vec<LspLogId>,
) {
    // Get next log ID.
    let log_id = &mut instance.state.spf_log_next_id;
    *log_id += 1;

    // Get trigger LSPs in log format.
    trigger_lsps.truncate(SPF_LOG_TRIGGER_LSPS_MAX_SIZE);

    // Add new log entry.
    let log_entry = SpfLogEntry::new(
        *log_id,
        spf_type,
        level,
        schedule_time,
        start_time,
        end_time,
        trigger_lsps,
    );
    instance.state.spf_log.push_front(log_entry);

    // Remove old entries if necessary.
    instance.state.spf_log.truncate(SPF_LOG_MAX_SIZE);
}
