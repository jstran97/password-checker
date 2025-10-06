import requests
import hashlib


def request_api_data(query_char):
    # Password API URL + our password input
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    # <Response [200]> is desired, not [400]
    # print(response.status_code)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, Check the API and try again.')
    # If no error, then return response from URL
    # Get a List of Entries (from the PwnedPasswords API) separated by a colon (:)
    # 1) Suffix of every Hashed Passwords beginning with the specified prefix
    # 2) Number of times the password hash with same First 5 characters appears in the data set
    return response

def pwned_api_check(password):
    # sha1password = hashlib.sha1(password.encode('utf-8')).hexdig
    # pass

    # Note: Unicode-objects must be encoded into hexadecimal digits (base 16) before hashing.

    # Encodes the password string as as Binary. Password string will be in UTF-8 format before going through Hash Function / Algorithm.
    print(password.encode('utf-8'))
    pw_encoded_in_utf8 = password.encode('utf-8')

    # SHA1 hash password (gibberish) (hex digits (base 16) only as double length string) (everything in uppercase)
    print(hashlib.sha1(pw_encoded_in_utf8).hexdigest().upper())
    sha1_pw_in_hex_digits = hashlib.sha1(pw_encoded_in_utf8).hexdigest().upper()

    first5_char_of_sha1pw = sha1_pw_in_hex_digits[:5]
    tail_of_sha1pw = sha1_pw_in_hex_digits[5:]

    response = request_api_data(first5_char_of_sha1pw)
    # print(first5_char_of_sha1pw, tail_of_sha1pw)
    # read_response(response)

    return get_password_leaks_count(response, tail_of_sha1pw)

def read_response(response):
    # Note: Number at the end of the response (from PASSWORD API URL) = HOW MANY TIMES the password was hacked / pwned
    # response.text = gives us ALL of the SHA1 HASHED passwords that MATCH our SHA1 HASHED password/output (from SHA1 Hash Algorithm / hashlib)
    print(response.text)


def get_password_leaks_count(hashes_from_api, our_pw_hash_to_check):
    """
    Split response (from Password API URL) (that we get AFTER we send the first 5 characters of our SHA1 Hash Output (from SHA1 Hash Alg / hashlib module))into 2 parts (a tuple of ()):
        1) SHA1 Hash Output (from SHA1 Hash Algorithm / hashlib)
        2) # of times the password was hacked / pwned
    """
    # Convert response (from Password API URL) into a tuple.
    hashes_from_api = (line.split(':') for line in hashes_from_api.text.splitlines())
    # print(hashes)

    for h, count in hashes_from_api:
        print(h, count)

        # Check if our hashed password (tail = hash to check) matches any entry from the list of hashed passwords from API.
        if h == our_pw_hash_to_check:
            return count

    # If there's no password match, return 0, meaning that our password does not exist in web API list of leaked/hacked passwords.
    return 0

# request_api_data('123')
pwned_api_check('123')