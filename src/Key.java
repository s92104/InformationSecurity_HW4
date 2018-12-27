import java.math.BigInteger;

public class Key {
	public BigInteger p;
	public BigInteger q;
	public BigInteger a;
	public BigInteger d;
	public BigInteger b;
	
	Key(BigInteger p,BigInteger q,BigInteger a,BigInteger d,BigInteger b)
	{
		this.p=p;
		this.q=q;
		this.a=a;
		this.b=b;
		this.d=d;
	}
}
