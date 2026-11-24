from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode

def encrypt(m, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(m)

def decrypt(c, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(c)

def keygen():
    phi = 65537
    e = 65537
    n = 1
    while gcd(phi, e) != 1:
        n = 1
        phi = 1
        p = random_prime(2^1048)
        q = next_prime(p + ZZ.random_element(2^15)) #to ensure that both primes have similar sizes
        n = p*q
        phi = (p-1)*(q-1)
    return RSA.construct((int(n), int(e), int(inverse_mod(e,phi))), consistency_check=True)
    
def test_decryption():
    print("-----Test 1-----")
    key = keygen()
    message = b"Hello, this is a test message for RSA."
    encrypted_message = encrypt(message, key.publickey())
    decrypted_message = decrypt(encrypted_message, key)
    print("Original message :", message.decode())
    print("Decrypted message:", decrypted_message.decode())

    print("-----Test 2-----")
    key = keygen()
    message = b"Another test message for RSA."
    encrypted_message = encrypt(message, key.publickey())
    decrypted_message = decrypt(encrypted_message, key)
    print("Original message :", message.decode())
    print("Decrypted message:", decrypted_message.decode())

    print("-----Test 3-----")
    key = keygen()
    message = b"Short message for RSA."
    encrypted_message = encrypt(message, key.publickey())
    decrypted_message = decrypt(encrypted_message, key)
    print("Original message :", message.decode())
    print("Decrypted message:", decrypted_message.decode())

def fermat_factor(n):
    a = math.isqrt(n) + 1
    while True:
        b_squared = a * a - n
        b = math.isqrt(b_squared)
        if b * b == b_squared:
            return (a - b, a + b)
        a += 1

def find_message():
    print("-----Find Message-----")

    key = b'-----BEGIN PUBLIC KEY-----\nMIIBJzANBgkqhkiG9w0BAQEFAAOCARQAMIIBDwKCAQYN2q/YoG8Fx8ci4wuhN2wR\nwVZafTqUvd8rxblpzLM0rwnHhNkLOuhqj9zJd2viW4ZjvggzA3VciC2wLWseLrP5\nN6VYQQqKkqFF8pQxml5qZsDlif1pm5Y3aF28BYdyfXjHfFyaiaA3QJvCNIz8Kxzq\nNd1DKAc1y31Un477kG/UEwqipeWdNBPO1AWieJ8sp4LjmOZ0dE8uBbwlZe5BzvBU\nTqOzHcdm/It5PSNkK94yahhyaLhI1Xt8Chw2FXKyUIUU5FDvirHx0qBju3Lp//Ja\nkCE+DroP8SG9sO8yn+CaPo79GReIwKAU6ibmMcXXWNsY6SwlucHEvk8iyJDlIjAM\ngPp+cN3XAgMBAAE=\n-----END PUBLIC KEY-----'
    c = b64decode(b'Db+NEKTa+qCXenwlQhKKxaiycSnvyN8v0+Tz27GTYmGQXhOS0n3HPlu7WiIY0h/3Ip5MOoJ/5Rx6UEHbaIpL8neJXL8d3rw3kfSXfyqur6n6DTgDq0FtubHExMc6b4QLMlVY9mVKsrmyqP5oH0VVssE6QJS8lP2e3GcmR0cnuLYOVzRt2ghBaV60y8Xo6sHn7UdB67ZoIYuhYqkhYLTrHjMDtrymev7SC1989ZfqJqofaSi1PvL6eB+5AC04OsHATKnwhFJj88nkrsc8a7vSQcjAv8Ru+jdnTCOyyjMdnxB0XlnC0LRiQQMhNhGHWuQzfp5Y7yji0sbpe9ilxH2H1yj5WQd10g==')

    pub_key = RSA.importKey(key)
    n = pub_key.n
    e = pub_key.e

    p, q = fermat_factor(n)
    d = inverse_mod(e, (p-1)*(q-1))
    priv_key = RSA.construct((n, e, int(d), int(p), int(q)))

    decrypted_message = decrypt(c, priv_key)
    print("Decrypted message:", decrypted_message.decode())

def main():
    test_decryption()
    find_message()

if __name__ == "__main__":
    main()