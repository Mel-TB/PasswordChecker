import requests
import hashlib


def request_api_data(query_char):
    # Password need to be hashed and give the 5 first char
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, try again')
    return response


def get_leaks_password_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        print(h, count)

def pwned_api_check(password):
    # Hash password using sha1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(response)
    return get_leaks_password_count(response, tail)
    # Check password if exist in API response


pwned_api_check('123')
