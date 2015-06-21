package cipher;

/**
 * Abstract class to convert byte arrays to longs for encrypting 64 bit byte
 * arrays as longs.
 * 
 * @author Dinesh Mendhe.
 */
public abstract class BlockCipher64 implements BlockCipher {
	/**
	 * Encrypt a block of plaintext using the given key. The block size is 64 / 8 bytes.
	 * bits. The length of the key and the block must be eight bytes.
	 * 
	 * @param key
	 *            the encryption key
	 * @param block
	 *            the block to encrypt (plaintext)
	 * @return the ciphertext encrypted with the given key
	 */
	public byte[] encrypt(byte[] key, byte[] block) {
		return longToByteArray(encrypt(byteArrayToLong(key),
				byteArrayToLong(block)));
	}

	/**
	 * Encrypt a block of plaintext using the given key. The block size is 64
	 * bits.
	 * 
	 * @param key
	 *            the encryption key as a long
	 * @param block
	 *            the block to encrypt (plaintext) as a long
	 * @return the ciphertext encrypted with the given key as a long
	 */
	public abstract long encrypt(long key, long block);

	/**
	 * Decrypt a block of ciphertext using the given key. The block size is 64
	 * bits. The length of the key and the block must be eight bytes.
	 * 
	 * @param key
	 *            the decryption key
	 * @param block
	 *            the block to decrypt (ciphertext)
	 * @return the plaintext decrypted with the given key
	 */
	public byte[] decrypt(byte[] key, byte[] block) {
		return longToByteArray(decrypt(byteArrayToLong(key),
				byteArrayToLong(block)));
	}

	/**
	 * Decrypt a block of ciphertext using the given key. The block size is 64
	 * bits.
	 * 
	 * @param key
	 *            the decryption key as a long
	 * @param block
	 *            the block to decrypt (ciphertext) as a long
	 * @return the plaintext decrypted with the given key as a long
	 */
	public abstract long decrypt(long key, long block);

	/**
	 * Convert a 64-bit byte array to a long.
	 * 
	 * @param block
	 *            the 64-bit block as a byte array
	 * @return the block as a long
	 */
	private long byteArrayToLong(byte[] block) {
		long lock = 0L;
		for (int i = 0; i < 8; i++)
			lock = (lock << 8) | (block[i] & 0xFFL);
		return lock;
	}

	/**
	 * Convert a 64-bit long to a byte array.
	 * 
	 * @param lock
	 *            the 64-bit block as a long
	 * @return the block as a byte array
	 */
	private byte[] longToByteArray(long lock) {
		byte[] block = new byte[8];
		for (int i = 7; i >= 0; i--) {
			block[i] = (byte) (lock & 0xFFL);
			lock = lock >> 8;
		}
		return block;
	}
}
