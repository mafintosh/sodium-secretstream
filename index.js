const sodium = require('sodium-universal')

const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
const TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
const TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
const STATEBYTES = sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES
const HEADERBYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
const KEYBYTES = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES

if (!TAG_FINAL) throw new Error('JavaScript sodium version needs to support crypto_secretstream_xchacha20poly')

const FINAL = TAG_FINAL[0]
const EMPTY = Buffer.alloc(0)
const TMP = Buffer.alloc(1)

class Push {
  constructor (key, state = Buffer.allocUnsafe(STATEBYTES), header = Buffer.allocUnsafe(HEADERBYTES)) {
    this.key = key
    this.state = state
    this.header = header

    sodium.crypto_secretstream_xchacha20poly1305_init_push(this.state, this.header, this.key)
  }

  next (message, cipher = Buffer.allocUnsafe(message.length + ABYTES)) {
    sodium.crypto_secretstream_xchacha20poly1305_push(this.state, cipher, message, null, TAG_MESSAGE)
    return cipher
  }

  final (message = EMPTY, cipher = Buffer.allocUnsafe(ABYTES)) {
    sodium.crypto_secretstream_xchacha20poly1305_push(this.state, cipher, message, null, TAG_FINAL)
    return cipher
  }
}

class Pull {
  constructor (key, state = Buffer.allocUnsafe(STATEBYTES)) {
    this.key = key
    this.state = Buffer.allocUnsafe(STATEBYTES)
    this.final = false
  }

  init (header) {
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(this.state, header, this.key)
  }

  next (cipher, message = Buffer.allocUnsafe(cipher.length - ABYTES)) {
    sodium.crypto_secretstream_xchacha20poly1305_pull(this.state, message, TMP, cipher, null)
    this.final = TMP[0] === FINAL
    return message
  }
}

function keygen (buf = Buffer.alloc(KEYBYTES)) {
  sodium.crypto_secretstream_xchacha20poly1305_keygen(buf)
  return buf
}

module.exports = {
  keygen,
  KEYBYTES,
  ABYTES,
  STATEBYTES,
  HEADERBYTES,
  Push,
  Pull
}
