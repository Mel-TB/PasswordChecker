from sys import argv, exit
import requests
import hashlib

# Function to make API request to check if password has been compromised
def request_api_data(query_char):
    # Passwords are hashed and checked using the first 5 characters of the hash
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)

    # Check for successful API response
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, try again')

    return response

# Function to parse API response and find the count of compromised password
def get_leaks_password_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())

    # Check if given hash matches any entries
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Function to check if password has been compromised
def pwned_api_check(password):
    # Hash password using SHA-1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]

    # Check if password's hash prefix exist in API response
    response = request_api_data(first5_char)
    return get_leaks_password_count(response, tail)

# Main function to handle CLI arguments and initiate password checks
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Your password: {password} was found {count} times...')
        else:
            print(f'Your password: {password} was not found')
    return 'Done !'


if __name__ == '__main__':
    exit(main(argv[1:]))
