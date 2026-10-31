from neesha.resolvers.dns import parse_txt_data


def test_parse_txt_single():
    assert parse_txt_data('"v=spf1 -all"') == "v=spf1 -all"


def test_parse_txt_multiple_strings_concatenated():
    assert parse_txt_data('"v=spf1 " "include:x ~all"') == "v=spf1 include:x ~all"
