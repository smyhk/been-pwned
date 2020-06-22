import requests
import hashlib


def request_api_data(query_char):
    url = f"https://api.pwnedpasswords.com/range/{query_char}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"error fetching: {res.status_code}, check the api and try again")

    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        print(h, count)


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first_5_chars, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5_chars)

    return get_password_leaks_count(response, tail)


pwned_api_check("123")
