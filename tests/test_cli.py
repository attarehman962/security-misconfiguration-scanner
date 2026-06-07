from scanner.cli import build_parser


def test_build_parser_accepts_valid_arguments() -> None:
    parser = build_parser()

    parsed = parser.parse_args(
        ["--url", "https://example.com", "--format", "json"]
    )

    assert parsed.url == "https://example.com"
    assert parsed.format == "json"
