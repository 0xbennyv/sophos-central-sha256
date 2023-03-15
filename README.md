# SOPHOS Central Block SHA
This tool has been designed to block SHA256 in Sohpos Central via the API. This tool can either use a CSV using the --file option or you can directly use --sha and --comment.

There's also a switch for Sophos Labs Intelix --intelix, this reaches out to SophosLabs to validate the SHA against detection first. Why block something already blocked? This uses the Intelix Free Tier API so make an account and get an API Key https://www.sophos.com/en-us/intelix.

example:

## With Intelix Validation
app.py --sha a718f907745f38bbd7ac123ea148a47ed5b15fab99d409a0d6b22707cb7beaea --comment "0xBennyV Binary" --intelix

## Without Intelix Validation
app.py --sha a718f907745f38bbd7ac123ea148a47ed5b15fab99d409a0d6b22707cb7beaea --comment 0xBennyV

## CSV With Intelix Validation
app.py --file test.csv --intelix --output

## CSV Without Intelix Validation
app.py --file test.csv --output
