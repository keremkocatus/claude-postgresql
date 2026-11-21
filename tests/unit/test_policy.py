import pytest

from ratatoskr.auth.policy import ConnectionNotFoundError, InsufficientAccessError, Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import Access
from tests.fakes import make_config

CONFIG = make_config(
    connections={
        "prod": {"mode": "read"},
        "staging": {"mode": "write"},
        "scratch": {"mode": "write"},
    },
    roles={
        "admins": {"*": "write"},
        "devops": {"prod": "read", "staging": "write"},
        "analyst": {"prod": "read"},
        "readers": {"*": "read"},
        "mixed": {"*": "read", "scratch": "write"},
    },
)
POLICY = Policy(CONFIG)


def _user(*groups: str) -> Principal:
    return Principal(subject="u", display_name="U", groups=frozenset(groups), auth_source="local")


@pytest.mark.parametrize(
    ("groups", "connection", "expected"),
    [
        (("admins",), "prod", Access.READ),  # mode: read caps even admins
        (("admins",), "staging", Access.WRITE),
        (("devops",), "prod", Access.READ),
        (("devops",), "staging", Access.WRITE),
        (("devops",), "scratch", Access.NONE),  # no grant -> deny by default
        (("analyst",), "staging", Access.NONE),
        (("readers",), "staging", Access.READ),  # wildcard
        (("mixed",), "scratch", Access.WRITE),  # max(wildcard read, explicit write)
        (("mixed",), "staging", Access.READ),
        (("analyst", "devops"), "staging", Access.WRITE),  # max over groups
        (("nobody",), "prod", Access.NONE),
        ((), "prod", Access.NONE),
        (("admins",), "ghost", Access.NONE),  # unknown connection
    ],
)
def test_effective_access_matrix(groups: tuple[str, ...], connection: str, expected: Access) -> None:
    assert POLICY.effective_access(_user(*groups), connection) == expected


def test_visible_connections_sorted_and_filtered() -> None:
    assert POLICY.visible_connections(_user("devops")) == [("prod", Access.READ), ("staging", Access.WRITE)]
    assert POLICY.visible_connections(_user("nobody")) == []


def test_authorize_returns_effective_access() -> None:
    assert POLICY.authorize(_user("devops"), "staging", Access.READ) == Access.WRITE


def test_unknown_and_forbidden_give_identical_error() -> None:
    with pytest.raises(ConnectionNotFoundError) as unknown:
        POLICY.authorize(_user("analyst"), "ghost", Access.READ)
    with pytest.raises(ConnectionNotFoundError) as forbidden:
        POLICY.authorize(_user("analyst"), "staging", Access.READ)
    assert str(unknown.value) == "Connection 'ghost' not found."
    assert str(forbidden.value) == "Connection 'staging' not found."
    assert type(unknown.value) is type(forbidden.value)


def test_write_needed_on_read_grant() -> None:
    with pytest.raises(InsufficientAccessError, match="Write access required on connection 'prod'."):
        POLICY.authorize(_user("admins"), "prod", Access.WRITE)
