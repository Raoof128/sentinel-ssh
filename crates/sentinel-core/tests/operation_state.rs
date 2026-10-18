use proptest::prelude::*;
use sentinel_core::effect::Effect;
use sentinel_core::identity::PrincipalId;
use sentinel_core::operation::{OperationRecord, OperationState, legal_transition};

#[test]
fn spec_transitions() {
    use OperationState::*;
    for (f, t) in [
        (Received, Authorised),
        (Received, Rejected),
        (Authorised, Queued),
        (Authorised, AwaitingApproval),
        (Queued, Running),
        (Running, Verifying),
        (Running, Succeeded),
        (Running, Failed),
        (Running, OutcomeUnknown),
        (Running, CancelRequested),
        (CancelRequested, Cancelled),
        (CancelRequested, OutcomeUnknown),
        (CancelRequested, Succeeded),
        (Verifying, Succeeded),
    ] {
        assert!(legal_transition(f, t), "{f:?}->{t:?}");
    }
    for (f, t) in [
        (Received, Running),
        (Succeeded, Running),
        (Rejected, Authorised),
        (Cancelled, Running),
        (Failed, Succeeded),
    ] {
        assert!(!legal_transition(f, t), "{f:?}->{t:?}");
    }
}

#[test]
fn transition_sets_finished_at_on_terminal() {
    let mut r = OperationRecord::new(PrincipalId::parse("p").unwrap(), None, "ssh_hosts_list", Effect::Read);
    assert_eq!(r.state, OperationState::Received);
    r.transition(OperationState::Authorised).unwrap();
    assert!(r.finished_at.is_none());
    r.transition(OperationState::Rejected).unwrap();
    assert!(r.is_terminal());
    assert!(r.finished_at.is_some());
}

fn any_state() -> impl Strategy<Value = OperationState> {
    proptest::sample::select(OperationState::ALL.to_vec())
}

proptest! {
    #[test]
    fn terminal_states_never_leave(seq in proptest::collection::vec(any_state(), 1..20)) {
        let mut r = OperationRecord::new(PrincipalId::parse("p").unwrap(), None, "ssh_hosts_list", Effect::Read);
        for s in seq {
            let was_terminal = r.is_terminal();
            let ok = r.transition(s).is_ok();
            if was_terminal { prop_assert!(!ok); }
        }
    }
}
