# PrivateNotesBackend
Back-end implementation designed for a private cloud-based note-taking application. Utilizes the cryptography library in Python to ensure security and privacy. Adversaries will not be able to learn anything about notes in the database that it does not specifically access (more about this in the threat model below).

Built to withstand a specific cryptographic threat model in which the adversary may submit four queries any number of times:
  -Insert: Adversary specifies a <title, note0, note1>. The challenger adds <title, noteB> to the database, where noteB is randomly chosen from note0 or note1.
  -Retrieve: Adversary specifies a title and the challenger replies with the associated note
   -Remove: The adversary specifies a title and the challenger removes said title/note pair from the database
   -Serialize: The challenger serializes the current contents of the application and sends this to the adversary. The adversary then gives the challenger a new string which they deserialize, and this becomes the new state of the application. (If the state of the application is ever detected as incorrect, the application should not function).

This backend is also built to withstand two specific attacks:
  -Swap Attack: The adversary switches the values corresponding to different keys (titles). Then, when the application user attempts to access one note, they share sensitive information about the other one instead.
  -Rollback Attack: The adversary can replace a note with a previous version of the same note. 
