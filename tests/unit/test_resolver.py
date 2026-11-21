from ratatoskr.auth.resolver import StdioPrincipalResolver


def test_stdio_principal_with_role() -> None:
    principal = StdioPrincipalResolver("admins").resolve()
    assert principal.subject == "stdio"
    assert principal.display_name == "local stdio user"
    assert principal.groups == frozenset({"admins"})
    assert principal.auth_source == "stdio"


def test_stdio_principal_without_role_has_no_groups() -> None:
    assert StdioPrincipalResolver(None).resolve().groups == frozenset()
