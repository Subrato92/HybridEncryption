package utilities;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RsaKeyExtractor {
	
	private BigInteger mod;
	private BigInteger pubExp;
	private BigInteger pvtExp;
	
	public RsaKeyExtractor(BigInteger mod, BigInteger pubExp) {
		this.mod = mod;
		this.pubExp = pubExp;
		this.pvtExp = null;
	}

	public RsaKeyExtractor(BigInteger mod, BigInteger pubExp, BigInteger pvtExp) {
		this.mod = mod;
		this.pubExp = pubExp;
		this.pvtExp = pvtExp;
	}
	
	public PrivateKey getPrivateKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidRsaKey {
		
		if(pvtExp==null || mod==null)
			throw new InvalidRsaKey("PrivateExponent or Modulus is Null");
		
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, pvtExp);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}
	
	public PublicKey getPublicKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidRsaKey {
		
		if(pvtExp==null || mod==null)
			throw new InvalidRsaKey("PublicExponent or Modulus is Null");
		
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, pubExp);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(keySpec);
		return pubKey;
	}
}
