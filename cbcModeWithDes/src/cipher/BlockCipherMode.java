package cipher;

/**
 * Interface to a block cipher mode. The block size can be any number of bytes.
 * 
 * @author Dinesh Mendhe.
 */
public interface BlockCipherMode {
	/**
	 * Set the initialization vector to the given value.
	 * 
	 * @param iv
	 * the initialization vector
	 */
	public void setIV(byte[] iv);

	/**
	 * Set the initialization vector to a random value.
	 */
	public void randomIV(); // This is optional. we can use either randomly generated IV or hardcoded IV. 

	/**
	 * Get the last initialization vector set or randomized.
	 * 
	 * @return the initialization vector
	 */
	public byte[] getIV();

	/**
	 * Encrypt an arbitrary number of bytes of plaintext using the given key.
	 * Plaintext must be padded
	 * 
	 * @param key
	 *            the encryption key
	 * @param plaintext
	 *            the data to encrypt
	 * @return the ciphertext encrypted with the given key
	 */
	public byte[] encrypt(byte[] key, byte[] plaintext);

	/**
	 * Decrypt an arbitrary number of bytes of ciphertext using the given key
	 * and IV encoded in the ciphertext.
	 * 
	 * @param key
	 *            the decryption key
	 * @param ciphertext
	 *            the data to decrypt
	 * @return the plaintext decrypted with the given key
	 */
	public byte[] decrypt(byte[] key, byte[] ciphertext);

}
