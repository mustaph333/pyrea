"""Sample target #1: a small pricing module.

PyREA should find: the TAX_RATE constant, the two functions, and the
derivation inside `total_with_tax`.
"""

TAX_RATE = 20

API_URL = "https://api.example-shop.com/v1/prices"


def price_after_discount(price, percent):
    return price - price * percent / 100


def total_with_tax(amount):
    return amount + amount * TAX_RATE / 100
