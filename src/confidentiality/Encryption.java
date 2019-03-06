package confidentiality;

import Exceptions.InvalidCipherNumberException;
import Exceptions.InvalidInitializationVectorException;
import Exceptions.InvalidKeyTypeException;
import algos.Tools;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class Encryption
{
  public static byte[] asymEnc(byte[] plain_text, String alg, PublicKey key, String[] provider)
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException
  {
     Cipher chiffrement_RSA = Cipher.getInstance(alg, Tools.getDefaultProvider(provider));
     chiffrement_RSA.init(1, key);

     return chiffrement_RSA.doFinal(plain_text);
  }

  public static byte[] symEnc(byte[] plain_text, String alg, SecretKey key, byte[] init_vector, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidInitializationVectorException
  {
     Cipher chiffrement = Cipher.getInstance(alg, Tools.getDefaultProvider(provider));

     if (alg.contains("CBC"))
    {
       if (init_vector == null) {
         throw new InvalidInitializationVectorException("The initialization vector parameter can't be null if you use CBC chaining");
      }
       chiffrement.init(1, key, new IvParameterSpec(init_vector));
    }
    else
    {
       chiffrement.init(1, key);
    }
     return chiffrement.doFinal(plain_text);
  }

  public static SealedObject sealedObjectEnc(Serializable object, String alg, Key key, byte[] init_vector, String[] provider)
    throws InvalidKeyTypeException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidInitializationVectorException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException
  {
     SealedObject so = null;

     if ((!(key instanceof PublicKey)) && (!(key instanceof SecretKey))) {
       throw new InvalidKeyTypeException();
    }
     Cipher chiffrement = Cipher.getInstance(alg, Tools.getDefaultProvider(provider));

     if (alg.contains("CBC"))
    {
       if (init_vector == null) {
         throw new InvalidInitializationVectorException("The initialization vector parameter can't be null if you use CBC mode");
      }
       chiffrement.init(1, key, new IvParameterSpec(init_vector));
    }
    else
    {
       chiffrement.init(1, key);
    }
     so = new SealedObject(object, chiffrement);

     return so;
  }

  public static SealedObject sealedObjectMultipleEnc(int nb_enc, Serializable object, List<String> algs, List<SecretKey> keys, byte[] init_vector, String[] provider)
    throws InvalidCipherNumberException, InvalidKeyTypeException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidInitializationVectorException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException
  {
     if (nb_enc <= 0) {
       throw new InvalidCipherNumberException("First parameter must be > 0");
    }
     if ((nb_enc != algs.size()) || (nb_enc != keys.size())) {
       throw new InvalidCipherNumberException("The number of keys/algos doesn't match the first parameter");
    }
     Serializable obj_to_encrypt = object;
     SealedObject so = null;

     for (int i = 0; i < nb_enc; i++) {
       if (i == nb_enc - 1)
         so = sealedObjectEnc(obj_to_encrypt, (String)algs.get(i), (Key)keys.get(i), init_vector, new String[0]);
      else {
         obj_to_encrypt = sealedObjectEnc(obj_to_encrypt, (String)algs.get(i), (Key)keys.get(i), init_vector, new String[0]);
      }
    }
     return so;
  }

  public static byte[] multipleSymEnc(int nb_enc, byte[] plain_text, List<String> algos, List<SecretKey> keys, byte[] init_vector, String[] provider)
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidCipherNumberException, InvalidAlgorithmParameterException, InvalidInitializationVectorException
  {
     if (nb_enc <= 0) {
       throw new InvalidCipherNumberException("First parameter must be > 0");
    }
     if ((nb_enc != algos.size()) || (nb_enc != keys.size())) {
       throw new InvalidCipherNumberException("The number of keys/algos doesn't match the first parameter");
    }
     byte[] cipher_text = plain_text;

     for (int i = 0; i < nb_enc; i++) {
       cipher_text = symEnc(cipher_text, (String)algos.get(i), (SecretKey)keys.get(i), init_vector, provider);
    }
     return cipher_text;
  }

  public static byte[] getRandomBytes(int vector_size)
  {
     byte[] vecteur_init = new byte[vector_size];
     new SecureRandom().nextBytes(vecteur_init);

     return vecteur_init;
  }

  public static byte[] getIVParameter() {
     return getRandomBytes(16);
  }

  static
  {
     Security.addProvider(new BouncyCastleProvider());
  }
}
