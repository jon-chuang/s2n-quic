use super::select::{self, Select};
use s2n_quic_core::{
    endpoint::Endpoint,
    event::{self, EndpointPublisher},
};

pub struct EventLoop<E: Endpoint, C: Clock> {
    pub clock: C,
    pub rx: crate::io::channel::Filled<E::PathHandle>,
    pub tx: crate::io::channel::Unfilled<E::PathHandle>,
    pub endpoint: E,
}

pub trait Clock: s2n_quic_core::time::Clock {
    type Timer: Timer;

    fn timer(&self) -> Self::Timer;
}

pub trait Timer: Unpin + core::future::Future<Output = ()> {
    fn update(&mut self, timestamp: s2n_quic_core::time::Timestamp);
}

impl<E: Endpoint, C: Clock> EventLoop<E, C> {
    pub async fn start(self) {
        let Self {
            clock,
            mut rx,
            mut tx,
            mut endpoint,
        } = self;

        let mut timer = clock.timer();

        loop {
            // Poll for readability if we have free slots available
            let rx_task = rx.ready();

            // Poll for writablity if we have occupied slots available
            let tx_task = tx.tx_ready();

            let wakeups = endpoint.wakeups(&clock);
            // pin the wakeups future so we don't have to move it into the Select future.

            // TODO use something else other than tokio
            tokio::pin!(wakeups);

            let select::Outcome {
                rx_result,
                tx_result,
                timeout_expired,
                application_wakeup,
            } = if let Ok(res) = Select::new(rx_task, tx_task, &mut wakeups, &mut timer).await {
                res
            } else {
                // The endpoint has shut down
                return;
            };

            let wakeup_timestamp = clock.get_time();
            let subscriber = endpoint.subscriber();
            let mut publisher = event::EndpointPublisherSubscriber::new(
                event::builder::EndpointMeta {
                    endpoint_type: E::ENDPOINT_TYPE,
                    timestamp: wakeup_timestamp,
                },
                None,
                subscriber,
            );

            publisher.on_platform_event_loop_wakeup(event::builder::PlatformEventLoopWakeup {
                timeout_expired,
                rx_ready: rx_result.is_some(),
                tx_ready: tx_result.is_some(),
                application_wakeup,
            });

            if let Some(Ok(())) = rx_result {
                if let Ok(mut rx_slice) = rx.try_slice() {
                    endpoint.receive(&mut rx_slice, &clock);
                }
            }

            // ignore the tx_result; we always try to transmit
            let _ = tx_result;

            if let Ok(mut tx_slice) = tx.try_slice() {
                endpoint.transmit(&mut tx_slice, &clock);
            }

            let timeout = endpoint.timeout();

            if let Some(timeout) = timeout {
                timer.update(timeout);
            }

            let timestamp = clock.get_time();
            let subscriber = endpoint.subscriber();
            let mut publisher = event::EndpointPublisherSubscriber::new(
                event::builder::EndpointMeta {
                    endpoint_type: E::ENDPOINT_TYPE,
                    timestamp,
                },
                None,
                subscriber,
            );

            // notify the application that we're going to sleep
            let timeout = timeout.map(|t| t.saturating_duration_since(timestamp));
            publisher.on_platform_event_loop_sleep(event::builder::PlatformEventLoopSleep {
                timeout,
                processing_duration: timestamp.saturating_duration_since(wakeup_timestamp),
            });
        }
    }
}
