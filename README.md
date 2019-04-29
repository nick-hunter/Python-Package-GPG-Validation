# Python-Package-GPG-Validation

## Installation
This application requires Python 3, and a local GPG installation.

Run `pip install -r requirements.txt` to install the necessary Python dependancies.

Then run `python3 create_admin.py` to create your root user account. This script can also be ran to reset the root password.

Next, edit the config.py file to include accurate paths to the database and the location you wish to store your GPG keyring.

Finally, run `export FLASK_APP=server.py` and `flask run`

## API call
Python package signatures can be checked with the /api/verify/<name>/<version> route. The version number is optional, and will default to the most recent version.

For example, /api/verify/Flask returns the following:
`{"version": "1.0.2", "verified_status": "signature valid", "key_id": "7A1C87E3F5BC42A8", "timestamp": "05-02-2018 14:26:25", "latest_version": "1.0.2"}`

## Notes and Disclaimers
This application is still a work in progress, and should not be used in production for security reasons.
