#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskState {
    Observe = 0,
    Warn = 1,
    Contain = 2,
    Kill = 3,
}

impl RiskState {
    pub fn next(self) -> RiskState {
        match self {
            RiskState::Observe => RiskState::Warn,
            RiskState::Warn => RiskState::Contain,
            RiskState::Contain => RiskState::Kill,
            RiskState::Kill => RiskState::Kill,
        }
    }
}
