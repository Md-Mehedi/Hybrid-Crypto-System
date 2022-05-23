""" This class is taken from GeeksForGeeks """

import random
from xmlrpc.client import Boolean


class Prime:
  """ Generate any number of bits prime number and can do primarity testing """

  first_100_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                      31, 37, 41, 43, 47, 53, 59, 61, 67,
                      71, 73, 79, 83, 89, 97, 101, 103,
                      107, 109, 113, 127, 131, 137, 139,
                      149, 151, 157, 163, 167, 173, 179,
                      181, 191, 193, 197, 199, 211, 223,
                      227, 229, 233, 239, 241, 251, 257,
                      263, 269, 271, 277, 281, 283, 293,
                      307, 311, 313, 317, 331, 337, 347, 349]
  """ First 100 prime numbers """
  N = 16 
  """ Bit count of prime number """
  
  def random_of_bit(self, n) -> int:
    """ Return a random number of 'n' bit """
    return random.randrange(2**(n-1)+1, 2**n - 1)

  def get_probable_prime(self, n) -> int:
    '''Generate a prime candidate not divisible by first primes'''
    while True:
      # Obtain a random number
      pc = self.random_of_bit(n)

      # Test divisibility by pre-generated primes
      for divisor in self.first_100_primes:
        if pc % divisor == 0 and divisor**2 <= pc:
          break
      else: return pc

  def is_miller_rabin_passed(self, mrc) -> bool:
      '''Run 20 iterations of Rabin Miller Primality test'''
      maxDivisionsByTwo = 0
      ec = mrc-1
      while ec % 2 == 0:
          ec >>= 1
          maxDivisionsByTwo += 1
      assert(2**maxDivisionsByTwo * ec == mrc-1)

      def trialComposite(round_tester):
          if pow(round_tester, ec, mrc) == 1:
              return False
          for i in range(maxDivisionsByTwo):
              if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                  return False
          return True

      # Set number of trials here
      numberOfRabinTrials = 20
      for i in range(numberOfRabinTrials):
          round_tester = random.randrange(2, mrc)
          if trialComposite(round_tester):
              return False
      return True
  
  def get_prime_of_bit(self, N:int) -> int:
    while True:
      prime_candidate = self.get_probable_prime(N)
      if not self.is_miller_rabin_passed(prime_candidate):
          continue
      else:
          return prime_candidate
          break
 



