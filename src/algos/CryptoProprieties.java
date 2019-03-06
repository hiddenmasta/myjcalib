package algos;

public abstract interface CryptoProprieties
{
  public static final String ASYM_ALG = "RSA/None/OAEPWithSHA1AndMGF1Padding";
  public static final String ASYM_KEY_ALG = "RSA";
  public static final String SYM_ALG = "AES/CBC/PKCS5Padding";
  public static final String SYM_KEY_ALG = "AES";
  public static final String DIFFIE_HELLMAN_KEY_ALG = "ECDH";
  public static final String DIFFIE_HELLMAN_KEY_PAIR_ALG = "brainpoolp256r1";
  public static final String HMAC_ALG = "HMAC-SHA512";
  public static final String SIGNATURE_ALG = "SHA512withRSA";
  public static final String PROVIDER = "BC";
  public static final int SYM_INIT_VECTOR_SIZE = 16;
  public static final int SYM_KEY_LENGTH = 128;
  public static final int SYM_KEY_MAX_LENGTH = 256;
  public static final int ASYM_KEY_LENGTH = 2048;
  public static final int ASYM_KEY_MAX_LENGTH = 4096;
  public static final String HASH_ALG = "RIPEMD320";
  public static final String RECURSIVE_SYM_ALG1 = "AES/CBC/PKCS5Padding";
  public static final String RECURSIVE_SYM_ALG2 = "twofish/CBC/PKCS5Padding";
  public static final String RECURSIVE_SYM_ALG3 = "Serpent/CBC/PKCS5Padding";
  public static final String RECURSIVE_SYM_KEY_ALG1 = "AES";
  public static final String RECURSIVE_SYM_KEY_ALG2 = "serpent";
  public static final String RECURSIVE_SYM_KEY_ALG3 = "twofish";
  public static final String CERTIFICATE_SIGNATURE_ALG = "SHA512withRSA";
}
