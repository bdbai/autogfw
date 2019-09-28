use std::fmt::{Display, Formatter, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unknown,
    Pending,
    TimedOut,
    KnownDirect,
    KnownProxy,
}

impl Display for State {
    fn fmt(&self, fmt: &mut Formatter) -> Result {
        fmt.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Pending => "Pending",
            Self::TimedOut => "TimedOut",
            Self::KnownDirect => "KnownDirect",
            Self::KnownProxy => "KnownProxy",
        })
    }
}
