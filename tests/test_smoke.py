def test_package_imports():
    import aap
    assert aap.__version__  # any non-empty string


def test_v06_surface_still_exported():
    """v0.6 public names must remain importable. New names may be added but
    none may be removed without a deprecation cycle."""
    import aap

    v06_surface = {
        "__version__",
        "Address",
        "AgentCard",
        "DiscoveryIntroductionRequest",
        "DiscoveryIntroductionResponse",
        "DiscoveryQueryResponse",
        "Envelope",
        "EnvelopeError",
        "GroupInvitation",
        "GroupLeave",
        "GroupMembershipUpdate",
        "RelationshipAccept",
        "RelationshipDecline",
        "RelationshipProposal",
        "RelationshipRevoke",
        "ServiceFollowup",
        "ServiceFollowupGrant",
        "ServiceRequest",
        "ServiceResponse",
        "ServiceResponseStatus",
        "VerificationAttestation",
        "VerifyConfirmResponse",
        "VerifyStartResponse",
        "VerifiedIdentity",
        "VerifierTrustListEntry",
        "decode_b64url",
        "encode_b64url",
        "generate_keypair",
        "parse_trusted_verifiers",
        "seed_to_keypair",
        "sign",
        "verify",
    }
    exported = set(aap.__all__)
    missing = v06_surface - exported
    assert not missing, f"v0.6 surface regression: {missing}"
    for name in v06_surface:
        assert hasattr(aap, name), f"aap.{name} missing"
