import hashlib
import os
import pickle
import cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PrivNotes:
  MAX_NOTE_LEN = 2048;

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format, potentially tampered data
    """

    # If Data is passed in, reload previous salt (here because necessary in creating source key)
    if data:
      self.salt = data[0]
    else:
      self.salt = os.urandom(16)

    # Derive a 256 source key from the user's password (using 2,000,000 iterations of SHA-256)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.salt,
                     iterations=2000000, )
    self.source_key = kdf.derive(bytes(password, 'ascii'))


    # Generating new keys based on source key
    encKeyBytes = bytes("encryption", 'ascii')
    digestEnc = hmac.HMAC(self.source_key, hashes.SHA256())
    digestEnc.update(encKeyBytes)
    self.Enc_key = digestEnc.finalize()  # PRFs the source key for use as the Encryption key; new key for all future encryption

    hmacKeyBytes = bytes("HMAC", 'ascii')
    digestHMAC = hmac.HMAC(self.source_key, hashes.SHA256())
    digestHMAC.update(hmacKeyBytes)
    self.HMAC_key = digestHMAC.finalize()  # PRFs the source key for use as the HMAC key; new key for all future HMACs

    passKeyBytes = bytes(password, 'ascii')
    digestPass = hmac.HMAC(self.source_key, hashes.SHA256())
    digestPass.update(passKeyBytes)
    self.PRFPassword = digestPass.finalize()  # PRFs the password for use in checking in init


    # If Data is passed in, reload previous nonce and data, then check data against checksum
    if data:
      self.isValidState = True                                #initially true, can be proven wrong though

      loadNonce = data[1]
      self.nonceNumber = int.from_bytes(loadNonce, 'little')
      passwordChecker = data[2]
      data = data[3]

      # Check password against stored HMACed password
      if passwordChecker != self.PRFPassword:
        assert ValueError("ERROR: Incorrect Password")
        self.isValidState = False

      dataToBytes = bytes(data, 'ascii')
      digest = hashes.Hash(hashes.SHA256())
      digest.update(dataToBytes)
      dataChecker = digest.finalize()
      if dataChecker != checksum:                                   #checks if data has been modified (compares to checksum)
        assert ValueError("data inconsistent with checksum")
        self.isValidState = False

    # If data is not passed in, we don't check data and therefore the state is valid by vacuous truth
    else:
      self.isValidState = True
      self.nonceNumber = 0


    self.kvs = {}

    if data is not None:
      self.kvs = pickle.loads(bytes.fromhex(data))

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    if not self.isValidState:
      assert ValueError("ERROR: Invalid State")

    # Convert data being passed on into bytes, then hash using SHA-256 to ensure security
    hexSerialization = pickle.dumps(self.kvs).hex()
    hexSBytes = bytes(hexSerialization, 'ascii')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(hexSBytes)
    checksum = digest.finalize()

    dumpNonce = (self.nonceNumber).to_bytes(16, 'little')

    # Return data in specific order so that init may access these fields
    return [self.salt, dumpNonce, self.PRFPassword, hexSerialization], checksum

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """

    if not self.isValidState:
      assert ValueError("ERROR: Invalid State")

    # Hash the title
    hashedTitle = self.hashTitle(title)

    # Hash the title AGAIN for swap protection (associated data parameter)
    hashDigest2 = hmac.HMAC(self.HMAC_key, hashes.SHA256())
    hashDigest2.update(hashedTitle)
    hashedTitle2 = hashDigest2.finalize()

    if hashedTitle in self.kvs:
      currentNote = self.kvs[hashedTitle]

      # AE decryption for note (AES-GCM)
      thisNonce = currentNote[:16]
      currentNote = currentNote[16:]
      aesgcm = AESGCM(self.Enc_key)
      pt = aesgcm.decrypt(thisNonce, currentNote, associated_data=hashedTitle2)

      # Gets rid of padding
      chopind = len(pt) - 1
      while pt[chopind] == 0:
        chopind -= 1
      pt = pt[:chopind]

      pt = pt.decode("ascii")                     # changes byte string to string
      return pt

    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """

    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')

    if not self.isValidState:
      assert ValueError("ERROR: Invalid State")

    # Hash the title
    hashedTitle = self.hashTitle(title)

    # Hash the title AGAIN for swap protection (associated data parameter)
    hashDigest2 = hmac.HMAC(self.HMAC_key, hashes.SHA256())
    hashDigest2.update(hashedTitle)
    hashedTitle2 = hashDigest2.finalize()

    # Padding the plaintext so that outside parties can't learn anything about message size
    bitNote = bytes(note, 'ascii')
    bitNote = bitNote + b"\x01"
    while len(bitNote) < self.MAX_NOTE_LEN:
      bitNote += b"\x00"

    # AE encryption for note (AES-GCM)
    thisNonce = (self.nonceNumber).to_bytes(16, 'little')
    aesgcm = AESGCM(self.Enc_key)
    ct = aesgcm.encrypt(thisNonce, bitNote, associated_data=hashedTitle2)

    self.kvs[hashedTitle] = thisNonce + ct

    self.nonceNumber = self.nonceNumber + 1


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """

    if not self.isValidState:
      assert ValueError("ERROR: Invalid State")

    # Hash the title
    hashedTitle = self.hashTitle(title)

    if hashedTitle in self.kvs:
      del self.kvs[hashedTitle]
      return True

    return False


  def hashTitle(self, title):

    if not self.isValidState:
      assert ValueError("ERROR: Invalid State")

    bitTitle = bytes(title, 'ascii')

    # Hash the title
    hashedTitle = hmac.HMAC(self.HMAC_key, hashes.SHA256())
    bitTitle = bytes(title, 'ascii')
    hashedTitle.update(bitTitle)
    hashed = hashedTitle.finalize()

    return hashed
