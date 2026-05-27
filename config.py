import os

# Flag - set via environment variable or use default
FLAG = os.environ.get("FLAG", "QA{r3d4ct3d}")

# Flag is encrypted at this byte offset in the keystream
# Players can only get keystream from positions 0 to MAX_KEYSTREAM_START
# They need to recover the key to compute keystream at FLAG_OFFSET
FLAG_OFFSET = int(os.environ.get("FLAG_OFFSET", "131072"))  # 2^17

# Maximum start position for keystream oracle
MAX_KEYSTREAM_START = int(os.environ.get("MAX_KEYSTREAM_START", "8000"))

# Maximum bytes per keystream request
MAX_KEYSTREAM_LENGTH = int(os.environ.get("MAX_KEYSTREAM_LENGTH", "2000"))

# Server configuration
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
