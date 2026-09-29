//! Core of lockout: local rules, the holdback guard and the audience policy.
//!
//! Everything here is synchronous and does no I/O. Feed generated text to a
//! [`Guard`] as it arrives, and pass on only what it releases.

pub mod detect;
pub mod guard;
pub mod normalize;
pub mod policy;

pub use detect::{Allow, Detectors};
pub use guard::{Event, Finding, Guard, Mode, SegmentConfig};
pub use policy::{Action, Audience, Category, Policy, Rules};
