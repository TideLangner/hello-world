# First legacy wallet
# Tide Langner
# 14 August 2022

from bitcoin import *

# Create private key
private_key = random_key()
print("Private key: " + private_key)

# Create public key
public_key = privtopub(private_key)
print("Public key: " + public_key)

# Create btc address
address = pubtoaddr(public_key)
print("BTC address: " + address)
