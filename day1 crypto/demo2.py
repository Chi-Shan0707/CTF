from secret import plaintext, mapping

alphabet = ' -()abcdefghijklmnopqrstuvwy'

ct = ''
for ch in plaintext:
    idx = alphabet.index(ch)
    ct += mapping[idx]

print(ct)